use std::collections::{BTreeMap, BTreeSet};

use super::{AsanaFamily, AsanaRecord};

/// One deterministic tenant-scoped Asana projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AsanaEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
}

/// One deterministic Asana projection relation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AsanaRelationFact {
    /// Source entity URN.
    pub from_urn: String,
    /// Closed semantic relation.
    pub relation: String,
    /// Target entity URN.
    pub to_urn: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AsanaProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<AsanaEntityFact>,
    /// Deduplicated relations in canonical order.
    pub relations: Vec<AsanaRelationFact>,
}

/// Project normalized Asana records into identity, project, and audit context.
pub fn project_asana_records(records: &[AsanaRecord]) -> AsanaProjectionFacts {
    let mut entities = BTreeMap::<String, AsanaEntityFact>::new();
    let mut relations = BTreeSet::new();
    for record in records {
        match record.family {
            AsanaFamily::Users | AsanaFamily::Projects => {
                if let Some(urn) = record.attributes.get("resource_urn") {
                    entities.insert(
                        urn.clone(),
                        AsanaEntityFact {
                            urn: urn.clone(),
                            entity_type: record.attributes["resource_type"].clone(),
                            label: record
                                .attributes
                                .get("resource_name")
                                .cloned()
                                .unwrap_or_else(|| record.provider_id.clone()),
                        },
                    );
                }
            }
            AsanaFamily::AuditEvents => {
                let actor_id = &record.attributes["actor_id"];
                let actor_urn =
                    format!("urn:cerebro:{}:runtime_users:{actor_id}", record.tenant_id);
                entities.insert(
                    actor_urn.clone(),
                    AsanaEntityFact {
                        urn: actor_urn.clone(),
                        entity_type: "identity_user".to_owned(),
                        label: record
                            .attributes
                            .get("actor_name")
                            .cloned()
                            .unwrap_or_else(|| actor_id.clone()),
                    },
                );
                if let Some(resource_urn) = record.attributes.get("resource_urn") {
                    entities.insert(
                        resource_urn.clone(),
                        AsanaEntityFact {
                            urn: resource_urn.clone(),
                            entity_type: record
                                .attributes
                                .get("resource_type")
                                .cloned()
                                .unwrap_or_else(|| "resource".to_owned()),
                            label: record
                                .attributes
                                .get("resource_name")
                                .cloned()
                                .unwrap_or_else(|| resource_urn.clone()),
                        },
                    );
                    relations.insert(AsanaRelationFact {
                        from_urn: actor_urn,
                        relation: "performed_action_on".to_owned(),
                        to_urn: resource_urn.clone(),
                    });
                }
            }
        }
    }
    AsanaProjectionFacts {
        entities: entities.into_values().collect(),
        relations: relations.into_iter().collect(),
    }
}
