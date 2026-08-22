use std::collections::{BTreeMap, BTreeSet};

use super::{AbuseIpDbFamily, AbuseIpDbRecord};

/// One deterministic tenant-scoped AbuseIPDB projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AbuseIpDbEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
}

/// One deterministic AbuseIPDB projection relation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AbuseIpDbRelationFact {
    /// Source entity URN.
    pub from_urn: String,
    /// Closed semantic relation.
    pub relation: String,
    /// Target entity URN.
    pub to_urn: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AbuseIpDbProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<AbuseIpDbEntityFact>,
    /// Deduplicated relations in canonical order.
    pub relations: Vec<AbuseIpDbRelationFact>,
}

/// Project normalized AbuseIPDB records into IP assets and findings.
pub fn project_abuseipdb_records(records: &[AbuseIpDbRecord]) -> AbuseIpDbProjectionFacts {
    let mut entities = BTreeMap::<String, AbuseIpDbEntityFact>::new();
    let mut relations = BTreeSet::<AbuseIpDbRelationFact>::new();
    for record in records {
        match record.family {
            AbuseIpDbFamily::IpAddresses => {
                let Some(resource_urn) = record.attributes.get("resource_urn") else {
                    continue;
                };
                entities.insert(
                    resource_urn.clone(),
                    AbuseIpDbEntityFact {
                        urn: resource_urn.clone(),
                        entity_type: "runtime.ip.address".to_owned(),
                        label: record
                            .attributes
                            .get("resource_name")
                            .cloned()
                            .unwrap_or_else(|| record.provider_id.clone()),
                    },
                );
            }
            AbuseIpDbFamily::Reports => {
                let Some(finding_id) = record.attributes.get("finding_id") else {
                    continue;
                };
                let finding_urn = format!(
                    "urn:cerebro:{}:finding:{}",
                    encode_segment(&record.tenant_id),
                    encode_segment(finding_id)
                );
                entities.insert(
                    finding_urn.clone(),
                    AbuseIpDbEntityFact {
                        urn: finding_urn.clone(),
                        entity_type: "finding".to_owned(),
                        label: record
                            .attributes
                            .get("title")
                            .cloned()
                            .unwrap_or_else(|| finding_id.clone()),
                    },
                );
                if let Some(resource_urn) = record.attributes.get("resource_urn") {
                    relations.insert(AbuseIpDbRelationFact {
                        from_urn: finding_urn,
                        relation: "affects".to_owned(),
                        to_urn: resource_urn.clone(),
                    });
                }
            }
        }
    }
    AbuseIpDbProjectionFacts {
        entities: entities.into_values().collect(),
        relations: relations.into_iter().collect(),
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
