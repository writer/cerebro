use std::collections::BTreeMap;

use super::{AhaFamily, AhaRecord};

/// One deterministic tenant-scoped Aha projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AhaEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AhaProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<AhaEntityFact>,
}

/// Project normalized Aha! records into identities, assets, and audit resources.
pub fn project_aha_records(records: &[AhaRecord]) -> AhaProjectionFacts {
    let mut entities = BTreeMap::<String, AhaEntityFact>::new();
    for record in records {
        let (urn, entity_type, label) = match record.family {
            AhaFamily::Features | AhaFamily::Products | AhaFamily::Releases => {
                let Some(urn) = record.attributes.get("resource_urn") else {
                    continue;
                };
                (
                    urn.clone(),
                    format!(
                        "runtime.{}",
                        record
                            .attributes
                            .get("resource_type")
                            .map(String::as_str)
                            .unwrap_or("asset")
                    ),
                    attribute(record, "resource_name"),
                )
            }
            AhaFamily::Users => (
                scoped_urn(record, "aha_user"),
                "aha.user".to_owned(),
                attribute(record, "display_name"),
            ),
            AhaFamily::AuditEvents => (
                format!(
                    "urn:cerebro:{}:runtime_{}:{}",
                    encode_segment(&record.tenant_id),
                    encode_segment(
                        record
                            .attributes
                            .get("resource_type")
                            .map(String::as_str)
                            .unwrap_or("resource")
                    ),
                    encode_segment(
                        record
                            .attributes
                            .get("resource_id")
                            .map(String::as_str)
                            .unwrap_or(&record.provider_id)
                    )
                ),
                "aha.audit_resource".to_owned(),
                attribute(record, "resource_name"),
            ),
        };
        entities.insert(
            urn.clone(),
            AhaEntityFact {
                urn,
                entity_type,
                label,
            },
        );
    }
    AhaProjectionFacts {
        entities: entities.into_values().collect(),
    }
}

fn scoped_urn(record: &AhaRecord, kind: &str) -> String {
    format!(
        "urn:cerebro:{}:{}:{}",
        encode_segment(&record.tenant_id),
        kind,
        encode_segment(&record.provider_id)
    )
}

fn attribute(record: &AhaRecord, key: &str) -> String {
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
