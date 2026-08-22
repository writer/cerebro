use std::collections::BTreeMap;

use super::{AdpFamily, AdpRecord};

/// One deterministic tenant-scoped ADP projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AdpEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdpProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<AdpEntityFact>,
}

/// Project normalized ADP records into workforce identities and audit resources.
pub fn project_adp_records(records: &[AdpRecord]) -> AdpProjectionFacts {
    let mut entities = BTreeMap::<String, AdpEntityFact>::new();
    for record in records {
        let (urn, entity_type, label) = match record.family {
            AdpFamily::Users => (
                format!(
                    "urn:cerebro:{}:adp_workforce_now_user:{}",
                    encode_segment(&record.tenant_id),
                    encode_segment(&record.provider_id)
                ),
                "adp_workforce_now.user".to_owned(),
                attribute(record, "display_name"),
            ),
            AdpFamily::EventNotifications => (
                format!(
                    "urn:cerebro:{}:adp_workforce_now_worker:{}",
                    encode_segment(&record.tenant_id),
                    encode_segment(
                        record
                            .attributes
                            .get("resource_id")
                            .map(String::as_str)
                            .unwrap_or(&record.provider_id)
                    )
                ),
                "adp_workforce_now.worker".to_owned(),
                attribute(record, "resource_id"),
            ),
        };
        entities.insert(
            urn.clone(),
            AdpEntityFact {
                urn,
                entity_type,
                label,
            },
        );
    }
    AdpProjectionFacts {
        entities: entities.into_values().collect(),
    }
}

fn attribute(record: &AdpRecord, key: &str) -> String {
    record
        .attributes
        .get(key)
        .cloned()
        .unwrap_or_else(|| record.provider_id.clone())
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
