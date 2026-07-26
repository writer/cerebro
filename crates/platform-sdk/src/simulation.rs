use serde::Serialize;

use crate::{
    AssertionDefinitionId, ContentDigest, EntityId, GraphRevision, RelationKind, SdkError,
    SimulationId, TenantId,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProposedChange {
    RemoveEntity {
        entity_id: EntityId,
    },
    RemoveRelationship {
        from_entity_id: EntityId,
        relation: RelationKind,
        to_entity_id: EntityId,
    },
    AddRelationship {
        from_entity_id: EntityId,
        relation: RelationKind,
        to_entity_id: EntityId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SimulationRequest {
    pub simulation_id: SimulationId,
    pub tenant_id: TenantId,
    pub base_revision: GraphRevision,
    pub changes: Vec<ProposedChange>,
    pub assertions: Vec<AssertionDefinitionId>,
    pub max_affected_entities: u32,
}

impl SimulationRequest {
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.changes.is_empty() {
            return Err(SdkError::Empty("simulation changes"));
        }
        if self.changes.len() > 100 {
            return Err(SdkError::OutOfRange("simulation changes"));
        }
        if self.max_affected_entities == 0 || self.max_affected_entities > 10_000 {
            return Err(SdkError::OutOfRange("simulation affected entity limit"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SimulationFinding {
    pub assertion_id: AssertionDefinitionId,
    pub before_state: String,
    pub after_state: String,
    pub reason_codes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SimulationResult {
    pub simulation_id: SimulationId,
    pub tenant_id: TenantId,
    pub base_revision: GraphRevision,
    pub applied_changes: Vec<ProposedChange>,
    pub affected_entities: Vec<EntityId>,
    pub assertion_results: Vec<SimulationFinding>,
    pub truncated: bool,
    pub result_digest: ContentDigest,
}
