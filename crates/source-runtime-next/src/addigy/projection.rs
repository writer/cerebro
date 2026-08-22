use std::collections::BTreeMap;

use super::{AddigyFamily, AddigyRecord};

/// One deterministic tenant-scoped Addigy projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AddigyEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AddigyProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<AddigyEntityFact>,
}

/// Project normalized Addigy records into devices, identities, policies, and audit resources.
pub fn project_addigy_records(records: &[AddigyRecord]) -> AddigyProjectionFacts {
    let mut entities = BTreeMap::<String, AddigyEntityFact>::new();
    for record in records {
        let (urn, entity_type, label) = match record.family {
            AddigyFamily::Devices => {
                let Some(urn) = record.attributes.get("resource_urn") else {
                    continue;
                };
                (
                    urn.clone(),
                    "runtime.device".to_owned(),
                    attribute(record, "resource_name"),
                )
            }
            AddigyFamily::Users => (
                scoped_urn(record, "addigy_user"),
                "addigy.user".to_owned(),
                attribute(record, "display_name"),
            ),
            AddigyFamily::Groups => (
                scoped_urn(record, "addigy_group"),
                "addigy.group".to_owned(),
                attribute(record, "group_name"),
            ),
            AddigyFamily::Policies => (
                scoped_urn(record, "policy"),
                "policy".to_owned(),
                attribute(record, "policy_name"),
            ),
            AddigyFamily::AuditEvents => (
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
                "addigy.audit_resource".to_owned(),
                attribute(record, "resource_name"),
            ),
        };
        entities.insert(
            urn.clone(),
            AddigyEntityFact {
                urn,
                entity_type,
                label,
            },
        );
    }
    AddigyProjectionFacts {
        entities: entities.into_values().collect(),
    }
}

fn scoped_urn(record: &AddigyRecord, kind: &str) -> String {
    format!(
        "urn:cerebro:{}:{}:{}",
        encode_segment(&record.tenant_id),
        kind,
        encode_segment(&record.provider_id)
    )
}

fn attribute(record: &AddigyRecord, key: &str) -> String {
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
