use std::collections::BTreeMap;

use super::{AkeneoFamily, AkeneoRecord};

/// One deterministic tenant-scoped Akeneo projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AkeneoEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AkeneoProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<AkeneoEntityFact>,
}

/// Project normalized Akeneo records with the same asset/group semantics as Go.
pub fn project_akeneo_records(records: &[AkeneoRecord]) -> AkeneoProjectionFacts {
    let mut entities = BTreeMap::<String, AkeneoEntityFact>::new();
    for record in records {
        let Some(urn) = record.attributes.get("resource_urn") else {
            continue;
        };
        let (entity_type, label_key) = if record.family == AkeneoFamily::AttributeGroup {
            ("akeneo.group".to_owned(), "group_name")
        } else {
            (
                format!(
                    "runtime.{}",
                    record
                        .attributes
                        .get("resource_type")
                        .map(String::as_str)
                        .unwrap_or("asset")
                        .replace('_', ".")
                ),
                "resource_name",
            )
        };
        entities.insert(
            urn.clone(),
            AkeneoEntityFact {
                urn: urn.clone(),
                entity_type,
                label: record
                    .attributes
                    .get(label_key)
                    .cloned()
                    .unwrap_or_else(|| record.provider_id.clone()),
            },
        );
    }
    AkeneoProjectionFacts {
        entities: entities.into_values().collect(),
    }
}
