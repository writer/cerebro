//! Deterministic in-memory projection of bounded graph-topology changes.
//!
//! The engine mutates a clone of caller-supplied topology and returns a receipt;
//! it never writes durable graph state. Topology loading, base-revision binding,
//! authorization, and assertion evaluation remain outside this module.

use std::collections::BTreeSet;

use cerebro_platform_sdk::{
    EntityId, ProposedChange, RelationKind, SdkError, SimulationFinding, SimulationRequest,
    SimulationResult, TenantId,
};
use serde::Serialize;

use crate::canonical;

/// Canonically ordered directed relationship in a simulation topology.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SimulationRelationship {
    /// Source entity identity.
    pub from_entity_id: EntityId,
    /// Directed relationship type.
    pub relation: RelationKind,
    /// Destination entity identity.
    pub to_entity_id: EntityId,
}

/// Fully materialized tenant topology used as simulation input.
///
/// Ordered sets make membership unique and receipt serialization deterministic.
/// This structure carries no graph revision, so the caller must prove that it
/// represents [`SimulationRequest::base_revision`] before invoking the engine.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SimulationTopology {
    /// Tenant asserted to own every entity and relationship.
    pub tenant_id: TenantId,
    /// Unique entity identities present in the projection.
    pub entities: BTreeSet<EntityId>,
    /// Unique directed relationships present in the projection.
    pub relationships: BTreeSet<SimulationRelationship>,
}

/// Applies a request atomically to an in-memory topology clone.
///
/// Changes run in request order. Removing an entity also removes every incident
/// relationship and counts both endpoints as affected; relationship changes
/// count their two endpoints. The hard affected-entity ceiling is checked after
/// each change, and exceeding it returns an error rather than a truncated result.
///
/// `assertion_results` are included as supplied. This function does not verify
/// that they are unique, correspond to `request.assertions`, or were evaluated
/// from the projected topology; the assertion-evaluation boundary owns that
/// binding. A successful digest covers the complete request, sorted affected
/// entities, ordered assertion results, and final projected topology.
///
/// # Errors
///
/// Returns request validation errors, [`SdkError::Invalid`] for a topology from
/// another tenant, [`SdkError::NotFound`] when a removal target or relationship
/// endpoint is absent, [`SdkError::Conflict`] when an added relationship already
/// exists, [`SdkError::OutOfRange`] when the affected-entity ceiling is exceeded
/// or cannot be represented, or [`SdkError::Backend`] if canonical serialization
/// fails. The caller-owned topology is unchanged on every error.
pub fn simulate_topology(
    request: &SimulationRequest,
    topology: &SimulationTopology,
    assertion_results: Vec<SimulationFinding>,
) -> Result<SimulationResult, SdkError> {
    request.validate()?;
    if request.tenant_id != topology.tenant_id {
        return Err(SdkError::Invalid("simulation tenant"));
    }
    let mut projected = topology.clone();
    let mut affected = BTreeSet::new();
    let max_affected = usize::try_from(request.max_affected_entities)
        .map_err(|_| SdkError::OutOfRange("simulation affected entity limit"))?;

    // Apply sequentially to the private clone so dependent changes see earlier
    // projected state without exposing a partial result when a later step fails.
    for change in &request.changes {
        match change {
            ProposedChange::RemoveEntity { entity_id } => {
                if !projected.entities.remove(entity_id) {
                    return Err(SdkError::NotFound(format!("simulation entity {entity_id}")));
                }
                affected.insert(entity_id.clone());

                // Removing incident edges affects their surviving peer entities
                // as well as the removed entity itself.
                projected.relationships.retain(|relationship| {
                    let retained = relationship.from_entity_id != *entity_id
                        && relationship.to_entity_id != *entity_id;
                    if !retained {
                        affected.insert(relationship.from_entity_id.clone());
                        affected.insert(relationship.to_entity_id.clone());
                    }
                    retained
                });
            }
            ProposedChange::RemoveRelationship {
                from_entity_id,
                relation,
                to_entity_id,
            } => {
                let relationship = SimulationRelationship {
                    from_entity_id: from_entity_id.clone(),
                    relation: *relation,
                    to_entity_id: to_entity_id.clone(),
                };
                if !projected.relationships.remove(&relationship) {
                    return Err(SdkError::NotFound("simulation relationship".to_owned()));
                }
                affected.extend([from_entity_id.clone(), to_entity_id.clone()]);
            }
            ProposedChange::AddRelationship {
                from_entity_id,
                relation,
                to_entity_id,
            } => {
                if !projected.entities.contains(from_entity_id)
                    || !projected.entities.contains(to_entity_id)
                {
                    return Err(SdkError::NotFound(
                        "simulation relationship endpoint".to_owned(),
                    ));
                }
                let relationship = SimulationRelationship {
                    from_entity_id: from_entity_id.clone(),
                    relation: *relation,
                    to_entity_id: to_entity_id.clone(),
                };
                if !projected.relationships.insert(relationship) {
                    return Err(SdkError::Conflict(
                        "simulation relationship already exists".to_owned(),
                    ));
                }
                affected.extend([from_entity_id.clone(), to_entity_id.clone()]);
            }
        }
        if affected.len() > max_affected {
            return Err(SdkError::OutOfRange("simulation affected entity limit"));
        }
    }
    let affected_entities = affected.into_iter().collect::<Vec<_>>();

    // BTree-backed topology and affected identities are already canonical; the
    // request and assertion vectors deliberately retain their semantic order.
    let result_digest =
        canonical::digest(&(request, &affected_entities, &assertion_results, &projected))?;
    Ok(SimulationResult {
        simulation_id: request.simulation_id.clone(),
        tenant_id: request.tenant_id.clone(),
        base_revision: request.base_revision,
        applied_changes: request.changes.clone(),
        affected_entities,
        assertion_results,
        truncated: false,
        result_digest,
    })
}

#[cfg(test)]
mod tests {
    use cerebro_platform_sdk::{GraphRevision, SimulationId};

    use super::*;

    #[test]
    fn adding_an_existing_relationship_is_a_conflict() {
        let left = EntityId::parse("repository:left").unwrap();
        let right = EntityId::parse("service:right").unwrap();
        let relationship = SimulationRelationship {
            from_entity_id: left.clone(),
            relation: RelationKind::Builds,
            to_entity_id: right.clone(),
        };
        let topology = SimulationTopology {
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            entities: BTreeSet::from([left.clone(), right.clone()]),
            relationships: BTreeSet::from([relationship]),
        };
        let request = SimulationRequest {
            simulation_id: SimulationId::parse("simulation:duplicate").unwrap(),
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            base_revision: GraphRevision::new(1).unwrap(),
            changes: vec![ProposedChange::AddRelationship {
                from_entity_id: left,
                relation: RelationKind::Builds,
                to_entity_id: right,
            }],
            assertions: Vec::new(),
            max_affected_entities: 10,
        };

        assert_eq!(
            simulate_topology(&request, &topology, Vec::new()),
            Err(SdkError::Conflict(
                "simulation relationship already exists".to_owned()
            ))
        );
    }
}
