#![forbid(unsafe_code)]

//! Rust-owned admission and current-state graph engine.

use std::{collections::BTreeMap, error::Error, fmt};

use cerebro_organizational_model::{
    AssertionId, Entity, EntityId, GraphAssertion, GraphDelta, IdentityBindingState,
    IdentityClaimKind, TenantId,
};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphError {
    EntityConflict(EntityId),
    MissingEntity(EntityId),
    IdentityAlreadyBound {
        provider_identity: EntityId,
        existing_canonical_identity: EntityId,
        requested_canonical_identity: EntityId,
    },
    IdentityClaimAlreadyBound {
        claim_kind: IdentityClaimKind,
        claim_value: String,
        existing_canonical_identity: EntityId,
        requested_canonical_identity: EntityId,
    },
    RetractionSourceMismatch(AssertionId),
}

impl fmt::Display for GraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntityConflict(id) => {
                write!(formatter, "entity {id} conflicts with stored identity")
            }
            Self::MissingEntity(id) => {
                write!(formatter, "assertion references missing entity {id}")
            }
            Self::IdentityAlreadyBound {
                provider_identity,
                existing_canonical_identity,
                requested_canonical_identity,
            } => write!(
                formatter,
                "provider identity {provider_identity} is already bound to {existing_canonical_identity}, not {requested_canonical_identity}",
            ),
            Self::RetractionSourceMismatch(id) => write!(
                formatter,
                "collection cannot retract assertion {id} owned by another source runtime"
            ),
            Self::IdentityClaimAlreadyBound {
                claim_kind,
                claim_value,
                existing_canonical_identity,
                requested_canonical_identity,
            } => write!(
                formatter,
                "identity claim {claim_kind:?}:{claim_value} is already bound to {existing_canonical_identity}, not {requested_canonical_identity}",
            ),
        }
    }
}

impl Error for GraphError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GraphWriteReceipt {
    pub tenant_id: TenantId,
    pub graph_revision: u64,
    pub delta_digest: String,
    pub entities_upserted: usize,
    pub assertions_upserted: usize,
    pub assertions_retracted: usize,
}

#[derive(Clone, Debug, Default)]
struct TenantGraph {
    revision: u64,
    entities: BTreeMap<EntityId, Entity>,
    assertions: BTreeMap<AssertionId, GraphAssertion>,
    confirmed_identity_bindings: BTreeMap<EntityId, EntityId>,
    confirmed_identity_claims: BTreeMap<(IdentityClaimKind, String), EntityId>,
}

#[derive(Clone, Debug, Default)]
pub struct OrganizationalGraph {
    tenants: BTreeMap<TenantId, TenantGraph>,
}

impl OrganizationalGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies a validated delta atomically. The candidate tenant graph is
    /// fully checked before it replaces current state.
    pub fn apply(&mut self, delta: GraphDelta) -> Result<GraphWriteReceipt, GraphError> {
        let tenant_id = delta.collection().tenant_id().clone();
        let mut candidate = self.tenants.get(&tenant_id).cloned().unwrap_or_default();

        for entity in delta.entities() {
            if let Some(existing) = candidate.entities.get(entity.id())
                && existing != entity
            {
                return Err(GraphError::EntityConflict(entity.id().clone()));
            }
            candidate
                .entities
                .insert(entity.id().clone(), entity.clone());
        }

        for assertion in delta.assertions() {
            self.validate_assertion_entities(&candidate, assertion)?;
            if let GraphAssertion::IdentityBinding(binding) = assertion
                && binding.state() == IdentityBindingState::Confirmed
            {
                if let Some(existing) = candidate
                    .confirmed_identity_bindings
                    .get(binding.provider_identity())
                    && existing != binding.canonical_identity()
                {
                    return Err(GraphError::IdentityAlreadyBound {
                        provider_identity: binding.provider_identity().clone(),
                        existing_canonical_identity: existing.clone(),
                        requested_canonical_identity: binding.canonical_identity().clone(),
                    });
                }
                candidate.confirmed_identity_bindings.insert(
                    binding.provider_identity().clone(),
                    binding.canonical_identity().clone(),
                );
                if let Some(claim) = binding.claim() {
                    let key = (claim.kind(), claim.value().to_owned());
                    if let Some(existing) = candidate.confirmed_identity_claims.get(&key)
                        && existing != binding.canonical_identity()
                    {
                        return Err(GraphError::IdentityClaimAlreadyBound {
                            claim_kind: claim.kind(),
                            claim_value: claim.value().to_owned(),
                            existing_canonical_identity: existing.clone(),
                            requested_canonical_identity: binding.canonical_identity().clone(),
                        });
                    }
                    candidate
                        .confirmed_identity_claims
                        .insert(key, binding.canonical_identity().clone());
                }
            }
            candidate
                .assertions
                .insert(assertion.id().clone(), assertion.clone());
        }

        let mut retracted = 0;
        for retraction in delta.retractions() {
            if let Some(assertion) = candidate.assertions.get(retraction.assertion_id()) {
                if assertion.provenance().source_runtime_id()
                    != delta.collection().source_runtime_id()
                {
                    return Err(GraphError::RetractionSourceMismatch(
                        retraction.assertion_id().clone(),
                    ));
                }
                if let GraphAssertion::IdentityBinding(binding) = assertion
                    && binding.state() == IdentityBindingState::Confirmed
                {
                    candidate
                        .confirmed_identity_bindings
                        .remove(binding.provider_identity());
                    if let Some(claim) = binding.claim() {
                        candidate
                            .confirmed_identity_claims
                            .remove(&(claim.kind(), claim.value().to_owned()));
                    }
                }
                candidate.assertions.remove(retraction.assertion_id());
                retracted += 1;
            }
        }

        candidate.revision = candidate.revision.saturating_add(1);
        let receipt = GraphWriteReceipt {
            tenant_id: tenant_id.clone(),
            graph_revision: candidate.revision,
            delta_digest: delta.digest().to_owned(),
            entities_upserted: delta.entities().len(),
            assertions_upserted: delta.assertions().len(),
            assertions_retracted: retracted,
        };
        self.tenants.insert(tenant_id, candidate);
        Ok(receipt)
    }

    fn validate_assertion_entities(
        &self,
        graph: &TenantGraph,
        assertion: &GraphAssertion,
    ) -> Result<(), GraphError> {
        let endpoints: [&EntityId; 2] = match assertion {
            GraphAssertion::Relationship(value) => [value.from(), value.to()],
            GraphAssertion::IdentityBinding(value) => {
                [value.provider_identity(), value.canonical_identity()]
            }
        };
        for endpoint in endpoints {
            if !graph.entities.contains_key(endpoint) {
                return Err(GraphError::MissingEntity(endpoint.clone()));
            }
        }
        Ok(())
    }
}

pub trait GraphRead {
    fn graph_revision(&self, tenant_id: &TenantId) -> u64;
    fn entity(&self, tenant_id: &TenantId, entity_id: &EntityId) -> Option<Entity>;
    fn entities(&self, tenant_id: &TenantId) -> Vec<Entity>;
    fn assertions(&self, tenant_id: &TenantId) -> Vec<GraphAssertion>;
}

impl GraphRead for OrganizationalGraph {
    fn graph_revision(&self, tenant_id: &TenantId) -> u64 {
        self.tenants
            .get(tenant_id)
            .map(|graph| graph.revision)
            .unwrap_or(0)
    }

    fn entity(&self, tenant_id: &TenantId, entity_id: &EntityId) -> Option<Entity> {
        self.tenants
            .get(tenant_id)?
            .entities
            .get(entity_id)
            .cloned()
    }

    fn entities(&self, tenant_id: &TenantId) -> Vec<Entity> {
        self.tenants
            .get(tenant_id)
            .map(|graph| graph.entities.values().cloned().collect())
            .unwrap_or_default()
    }

    fn assertions(&self, tenant_id: &TenantId) -> Vec<GraphAssertion> {
        self.tenants
            .get(tenant_id)
            .map(|graph| graph.assertions.values().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use cerebro_organizational_model::{
        AssertionProvenance, CanonicalIdentity, CanonicalIdentityId, CollectionId,
        CompleteCollection, GraphAssertion, IdentityBindingAssertion, IdentityBindingState,
        IdentityClaim, IdentityResolutionMethod, ObservationId, ObservationRef, ProviderIdentity,
        ProviderKind, SourceRuntimeId,
    };

    use super::*;

    fn identity_delta(
        provider_id: &str,
        canonical_id: &str,
        state: IdentityBindingState,
        claim: Option<IdentityClaim>,
    ) -> GraphDelta {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let runtime = SourceRuntimeId::parse("okta-prod").unwrap();
        let collection = CompleteCollection::new(
            tenant.clone(),
            runtime.clone(),
            CollectionId::parse(format!("collection-{canonical_id}")).unwrap(),
            "okta.users",
            10,
        )
        .unwrap();
        let provider = ProviderIdentity::new(
            tenant.clone(),
            runtime,
            ProviderKind::parse("okta.user").unwrap(),
            provider_id,
            "Provider Person",
        )
        .unwrap();
        let canonical = CanonicalIdentity::new(
            tenant,
            CanonicalIdentityId::parse(canonical_id).unwrap(),
            "Canonical Person",
        )
        .unwrap();
        let provenance = AssertionProvenance::direct(
            vec![
                ObservationRef::new(
                    collection.receipt(),
                    ObservationId::parse(format!("observation-{canonical_id}")).unwrap(),
                    format!("okta.user:{provider_id}"),
                )
                .unwrap(),
            ],
            "okta-identity-mapper",
            "v1",
        )
        .unwrap();
        let binding = IdentityBindingAssertion::new(
            &provider,
            &canonical,
            IdentityResolutionMethod::HumanDecision,
            claim,
            state,
            provenance,
            10,
        )
        .unwrap();
        let mut builder = collection.begin_delta();
        builder.add_entity(provider.into_entity()).unwrap();
        builder.add_entity(canonical.into_entity()).unwrap();
        builder
            .add_assertion(GraphAssertion::IdentityBinding(binding))
            .unwrap();
        builder.build()
    }

    #[test]
    fn one_provider_identity_cannot_bind_to_two_canonical_identities() {
        let mut graph = OrganizationalGraph::new();
        graph
            .apply(identity_delta(
                "00u1",
                "person-1",
                IdentityBindingState::Confirmed,
                None,
            ))
            .unwrap();
        assert!(matches!(
            graph.apply(identity_delta(
                "00u1",
                "person-2",
                IdentityBindingState::Confirmed,
                None,
            )),
            Err(GraphError::IdentityAlreadyBound { .. })
        ));
    }

    #[test]
    fn one_authoritative_claim_cannot_create_two_canonical_identities() {
        let mut graph = OrganizationalGraph::new();
        let first = identity_delta(
            "00u1",
            "person-1",
            IdentityBindingState::Confirmed,
            Some(IdentityClaim::employee_id("employee-1").unwrap()),
        );
        let second = identity_delta(
            "00u2",
            "person-2",
            IdentityBindingState::Confirmed,
            Some(IdentityClaim::employee_id("employee-1").unwrap()),
        );
        graph.apply(first).unwrap();
        assert!(matches!(
            graph.apply(second),
            Err(GraphError::IdentityClaimAlreadyBound { .. })
        ));
    }

    #[test]
    fn failed_delta_does_not_partially_change_graph() {
        let mut graph = OrganizationalGraph::new();
        graph
            .apply(identity_delta(
                "00u1",
                "person-1",
                IdentityBindingState::Confirmed,
                None,
            ))
            .unwrap();
        let revision = graph.graph_revision(&TenantId::parse("tenant-a").unwrap());
        let _ = graph.apply(identity_delta(
            "00u1",
            "person-2",
            IdentityBindingState::Confirmed,
            None,
        ));
        assert_eq!(
            graph.graph_revision(&TenantId::parse("tenant-a").unwrap()),
            revision
        );
    }
}
