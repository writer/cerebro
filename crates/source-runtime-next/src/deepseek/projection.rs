use std::collections::{BTreeMap, BTreeSet};

use super::DeepSeekRecord;

/// One deterministic tenant-scoped DeepSeek projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeepSeekEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed graph entity type.
    pub entity_type: String,
    /// Human-readable entity label.
    pub label: String,
}

/// One deterministic DeepSeek projection relation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeepSeekRelationFact {
    /// Source entity URN.
    pub from_urn: String,
    /// Closed semantic relation.
    pub relation: String,
    /// Target entity URN.
    pub to_urn: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeepSeekProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<DeepSeekEntityFact>,
    /// Deduplicated relations in canonical order.
    pub relations: Vec<DeepSeekRelationFact>,
}

/// Project normalized records using the existing Go projector semantics.
pub fn project_deepseek_records(records: &[DeepSeekRecord]) -> DeepSeekProjectionFacts {
    let mut entities = BTreeMap::<String, DeepSeekEntityFact>::new();
    let mut relations = BTreeSet::new();
    for record in records {
        let Some(resource_urn) = record.attributes.get("resource_urn") else {
            continue;
        };
        let resource_type = record
            .attributes
            .get("resource_type")
            .cloned()
            .unwrap_or_else(|| "asset".to_owned());
        entities.insert(
            resource_urn.clone(),
            DeepSeekEntityFact {
                urn: resource_urn.clone(),
                entity_type: format!("runtime.{}", resource_type.replace('_', ".")),
                label: record
                    .attributes
                    .get("resource_name")
                    .cloned()
                    .unwrap_or_else(|| record.provider_id.clone()),
            },
        );
        if let Some(evidence_id) = record.attributes.get("evidence_id") {
            let evidence_urn = format!(
                "urn:cerebro:{}:runtime_evidence:{evidence_id}",
                record.tenant_id
            );
            entities.insert(
                evidence_urn.clone(),
                DeepSeekEntityFact {
                    urn: evidence_urn.clone(),
                    entity_type: "runtime.evidence".to_owned(),
                    label: evidence_id.clone(),
                },
            );
            relations.insert(DeepSeekRelationFact {
                from_urn: resource_urn.clone(),
                relation: "has_evidence".to_owned(),
                to_urn: evidence_urn,
            });
        }
    }
    DeepSeekProjectionFacts {
        entities: entities.into_values().collect(),
        relations: relations.into_iter().collect(),
    }
}
