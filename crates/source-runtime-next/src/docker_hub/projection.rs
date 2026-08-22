use std::collections::BTreeMap;

use super::DockerHubRecord;

/// One deterministic tenant-scoped Docker Hub projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DockerHubEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable repository label.
    pub label: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DockerHubProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<DockerHubEntityFact>,
}

/// Project normalized repositories into the existing Go semantic shape.
pub fn project_docker_hub_records(records: &[DockerHubRecord]) -> DockerHubProjectionFacts {
    let mut entities = BTreeMap::<String, DockerHubEntityFact>::new();
    for record in records {
        if let Some(urn) = record.attributes.get("resource_urn") {
            entities.insert(
                urn.clone(),
                DockerHubEntityFact {
                    urn: urn.clone(),
                    entity_type: "runtime.container.repository".to_owned(),
                    label: record
                        .attributes
                        .get("resource_name")
                        .cloned()
                        .unwrap_or_else(|| record.provider_id.clone()),
                },
            );
        }
    }
    DockerHubProjectionFacts {
        entities: entities.into_values().collect(),
    }
}
