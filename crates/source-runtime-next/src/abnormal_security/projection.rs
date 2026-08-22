use std::collections::BTreeMap;

use super::AbnormalSecurityRecord;

/// One deterministic tenant-scoped projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AbnormalSecurityEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AbnormalSecurityProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<AbnormalSecurityEntityFact>,
}

/// Project normalized records into catalog entities.
pub fn project_abnormal_security_records(
    records: &[AbnormalSecurityRecord],
) -> AbnormalSecurityProjectionFacts {
    let mut entities = BTreeMap::<String, AbnormalSecurityEntityFact>::new();
    for record in records {
        let urn = format!(
            "urn:cerebro:{}:abnormal_security_{}:{}",
            encode_segment(&record.tenant_id),
            record.family.as_str(),
            encode_segment(&record.provider_id)
        );
        let label = record
            .attributes
            .get("resource_name")
            .or_else(|| record.attributes.get("policy_name"))
            .or_else(|| record.attributes.get("title"))
            .or_else(|| record.attributes.get("event_type"))
            .cloned()
            .unwrap_or_else(|| record.provider_id.clone());
        entities.insert(
            urn.clone(),
            AbnormalSecurityEntityFact {
                urn,
                entity_type: format!(
                    "abnormal_security.{}",
                    record.family.as_str().replace('_', ".")
                ),
                label,
            },
        );
    }
    AbnormalSecurityProjectionFacts {
        entities: entities.into_values().collect(),
    }
}

fn encode_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.trim().bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b':') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}
