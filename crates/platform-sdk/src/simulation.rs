//! Bounded, side-effect-free graph-topology simulation contracts.
//!
//! A simulation describes proposed graph changes at a declared base revision
//! and returns their projected impact. These types do not load that revision,
//! authorize the tenant, evaluate assertions, or execute an external action.

use serde::Serialize;

use crate::{
    AssertionDefinitionId, ContentDigest, EntityId, GraphRevision, RelationKind, SdkError,
    SimulationId, TenantId,
};

const MAX_SIMULATION_CHANGES: usize = 100;
const MAX_SIMULATION_ASSERTIONS: usize = 100;

/// Topology mutation applied to an in-memory simulation projection.
///
/// Variants intentionally cover removal of an entity and addition or removal
/// of a relationship. They do not create entities or mutate entity payloads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProposedChange {
    /// Remove an existing entity and all relationships incident to it.
    RemoveEntity {
        /// Stable identity of the entity to remove.
        entity_id: EntityId,
    },
    /// Remove one existing typed relationship.
    RemoveRelationship {
        /// Relationship source entity.
        from_entity_id: EntityId,
        /// Relationship type.
        relation: RelationKind,
        /// Relationship destination entity.
        to_entity_id: EntityId,
    },
    /// Add one typed relationship between two existing entities.
    AddRelationship {
        /// Relationship source entity.
        from_entity_id: EntityId,
        /// Relationship type.
        relation: RelationKind,
        /// Relationship destination entity.
        to_entity_id: EntityId,
    },
}

/// Bounded request to project a sequence of topology changes.
///
/// Changes are ordered and therefore may depend on earlier changes in the same
/// request. Assertion IDs select externally evaluated checks; the topology
/// engine accepts their results separately and does not evaluate them itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SimulationRequest {
    /// Caller-selected identity used to correlate request and result.
    pub simulation_id: SimulationId,
    /// Tenant whose topology is being modeled.
    pub tenant_id: TenantId,
    /// Declared graph revision from which the input topology was materialized.
    pub base_revision: GraphRevision,
    /// Ordered non-empty change sequence, bounded to 100 entries.
    pub changes: Vec<ProposedChange>,
    /// Assertion definitions to evaluate, bounded to 100 entries.
    pub assertions: Vec<AssertionDefinitionId>,
    /// Hard ceiling on distinct entities touched, in `1..=10_000`.
    pub max_affected_entities: u32,
}

impl SimulationRequest {
    /// Validates collection and affected-entity bounds.
    ///
    /// This shape check does not reject duplicate changes or assertions, prove
    /// that the base revision exists, or bind any referenced ID to the tenant.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Empty`] when no changes are supplied, or
    /// [`SdkError::OutOfRange`] when there are more than 100 changes, more than
    /// 100 assertions, or an affected-entity ceiling outside `1..=10_000`.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.changes.is_empty() {
            return Err(SdkError::Empty("simulation changes"));
        }
        if self.changes.len() > MAX_SIMULATION_CHANGES {
            return Err(SdkError::OutOfRange("simulation changes"));
        }
        if self.assertions.len() > MAX_SIMULATION_ASSERTIONS {
            return Err(SdkError::OutOfRange("simulation assertions"));
        }
        if self.max_affected_entities == 0 || self.max_affected_entities > 10_000 {
            return Err(SdkError::OutOfRange("simulation affected entity limit"));
        }
        Ok(())
    }
}

/// Caller-supplied before/after result for one requested assertion.
///
/// State and reason-code vocabularies are intentionally transport-neutral and
/// are not bounded or interpreted by the SDK type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SimulationFinding {
    /// Assertion definition whose outcome was compared.
    pub assertion_id: AssertionDefinitionId,
    /// Serialized assertion state before proposed changes.
    pub before_state: String,
    /// Serialized assertion state after proposed changes.
    pub after_state: String,
    /// Ordered machine-readable explanations for the transition.
    pub reason_codes: Vec<String>,
}

/// Deterministic receipt for a successful topology simulation.
///
/// The result reports a projection only; it is not proof that changes were
/// authorized, committed, or observed in the durable graph.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SimulationResult {
    /// Simulation identity copied from the request.
    pub simulation_id: SimulationId,
    /// Tenant identity copied from the request.
    pub tenant_id: TenantId,
    /// Declared base revision copied from the request.
    pub base_revision: GraphRevision,
    /// Complete ordered change sequence applied to the projection.
    pub applied_changes: Vec<ProposedChange>,
    /// Sorted distinct identities touched directly or by incident removal.
    pub affected_entities: Vec<EntityId>,
    /// Assertion comparisons supplied by the assertion-evaluation boundary.
    pub assertion_results: Vec<SimulationFinding>,
    /// Whether the result omits affected data because of a bounded response.
    pub truncated: bool,
    /// Canonical digest of the request and successful projected result material.
    pub result_digest: ContentDigest,
}
