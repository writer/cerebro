#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Rust-owned admission and current-state graph engine.
//!
//! The graph accepts only [`GraphDelta`] values that have already crossed the
//! sealed model's admission boundary. [`OrganizationalGraph::apply`] validates
//! the complete candidate tenant state before replacing current state, so a
//! failed entity, identity, claim, or retraction check cannot partially mutate
//! the graph. The graph is a current-state projection; durable replay and
//! persistence belong to the organizational-store crate.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use cerebro_organizational_model::{
    AssertionId, Entity, EntityId, GraphAssertion, GraphDelta, IdentityBindingState,
    IdentityClaimKind, IdentityResolutionMethod, TenantId,
};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq)]
/// A candidate graph delta violated an identity or ownership invariant.
pub enum GraphError {
    /// An incoming entity reused an ID with different stable identity fields.
    EntityConflict(EntityId),
    /// An assertion references an entity absent from both current and incoming state.
    MissingEntity(EntityId),
    /// A provider identity is already confirmed against another canonical identity.
    IdentityAlreadyBound {
        /// The provider-owned identity being rebound.
        provider_identity: EntityId,
        /// The canonical identity already confirmed for the provider identity.
        existing_canonical_identity: EntityId,
        /// The different canonical identity requested by the candidate delta.
        requested_canonical_identity: EntityId,
    },
    /// A normalized identity claim is already confirmed against another identity.
    IdentityClaimAlreadyBound {
        /// The namespace of the conflicting claim.
        claim_kind: IdentityClaimKind,
        /// The normalized claim value.
        claim_value: String,
        /// The canonical identity already confirmed for the claim.
        existing_canonical_identity: EntityId,
        /// The different canonical identity requested by the candidate delta.
        requested_canonical_identity: EntityId,
    },
    /// A canonical identity lacks the authoritative employee anchor required for binding.
    CanonicalIdentityUnanchored(EntityId),
    /// A proposed binding cites no confirmed claim for the requested identity.
    IdentityClaimNotFound {
        /// The namespace of the missing claim.
        claim_kind: IdentityClaimKind,
        /// The normalized claim value.
        claim_value: String,
        /// The canonical identity the claim was expected to anchor.
        requested_canonical_identity: EntityId,
    },
    /// A collection attempted to retract an assertion owned by another runtime.
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
            Self::CanonicalIdentityUnanchored(identity) => write!(
                formatter,
                "canonical identity {identity} has no authoritative employee anchor"
            ),
            Self::IdentityClaimNotFound {
                claim_kind,
                claim_value,
                requested_canonical_identity,
            } => write!(
                formatter,
                "identity claim {claim_kind:?}:{claim_value} is not authoritatively bound to {requested_canonical_identity}",
            ),
        }
    }
}

impl Error for GraphError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Receipt for one atomically accepted graph delta.
///
/// Counts describe writes in the submitted delta, while `graph_revision`
/// identifies the resulting tenant projection revision.
pub struct GraphWriteReceipt {
    /// Tenant whose projection changed.
    pub tenant_id: TenantId,
    /// Monotonic in-memory revision after the accepted write.
    pub graph_revision: u64,
    /// Content digest committed by the validated delta.
    pub delta_digest: String,
    /// Number of entities inserted or refreshed.
    pub entities_upserted: usize,
    /// Number of assertions inserted or refreshed.
    pub assertions_upserted: usize,
    /// Number of existing assertions removed by owned retractions.
    pub assertions_retracted: usize,
}

#[derive(Clone, Debug, Default)]
struct TenantGraph {
    revision: u64,
    entities: BTreeMap<EntityId, Entity>,
    assertions: BTreeMap<AssertionId, GraphAssertion>,
    confirmed_identity_bindings: BTreeMap<EntityId, EntityId>,
    confirmed_identity_claims: BTreeMap<(IdentityClaimKind, String), EntityId>,
    anchored_canonical_identities: BTreeSet<EntityId>,
}

#[derive(Clone, Debug, Default)]
/// Tenant-partitioned current-state organizational graph.
///
/// This type is an in-process projection engine, not a durable store. Clone-on-
/// validate admission preserves atomicity before the accepted candidate state
/// replaces a tenant's current assertion and identity indexes.
pub struct OrganizationalGraph {
    tenants: BTreeMap<TenantId, TenantGraph>,
}

impl OrganizationalGraph {
    /// Creates an empty graph with no tenant projections.
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies a validated delta atomically. The candidate tenant graph is
    /// fully checked before current state is mutated.
    pub fn apply(&mut self, delta: GraphDelta) -> Result<GraphWriteReceipt, GraphError> {
        let (collection, entities, assertions, retractions, delta_digest) = delta.into_components();
        let tenant_id = collection.tenant_id().clone();
        let entities_upserted = entities.len();
        let assertions_upserted = assertions.len();
        let current = self.tenants.get(&tenant_id);

        for entity in &entities {
            if let Some(existing) = current.and_then(|graph| graph.entities.get(entity.id()))
                && !existing.has_same_identity(entity)
            {
                return Err(GraphError::EntityConflict(entity.id().clone()));
            }
        }

        if assertions.is_empty() && retractions.is_empty() {
            let graph = self.tenants.entry(tenant_id.clone()).or_default();
            for entity in entities {
                graph.entities.insert(entity.id().clone(), entity);
            }
            graph.revision = graph.revision.saturating_add(1);
            return Ok(GraphWriteReceipt {
                tenant_id,
                graph_revision: graph.revision,
                delta_digest,
                entities_upserted,
                assertions_upserted,
                assertions_retracted: 0,
            });
        }

        let incoming_entity_ids = entities.iter().map(Entity::id).collect::<BTreeSet<_>>();
        let mut candidate_assertions = current
            .map(|graph| graph.assertions.clone())
            .unwrap_or_default();
        for assertion in assertions {
            Self::validate_assertion_entities(current, &incoming_entity_ids, &assertion)?;
            candidate_assertions.insert(assertion.id().clone(), assertion);
        }

        let mut retracted = 0;
        for retraction in retractions {
            if let Some(assertion) = candidate_assertions.get(retraction.assertion_id()) {
                if assertion.provenance().source_runtime_id() != collection.source_runtime_id() {
                    return Err(GraphError::RetractionSourceMismatch(
                        retraction.assertion_id().clone(),
                    ));
                }
                candidate_assertions.remove(retraction.assertion_id());
                retracted += 1;
            }
        }

        // Rebuild every identity index from the complete candidate assertion
        // set. Incremental index mutation could leave stale bindings when the
        // same delta retracts and replaces identity evidence.
        let mut identity_candidate = TenantGraph {
            assertions: candidate_assertions,
            ..TenantGraph::default()
        };
        identity_candidate.rebuild_identity_indexes()?;

        let graph = self.tenants.entry(tenant_id.clone()).or_default();
        for entity in entities {
            graph.entities.insert(entity.id().clone(), entity);
        }
        graph.assertions = identity_candidate.assertions;
        graph.confirmed_identity_bindings = identity_candidate.confirmed_identity_bindings;
        graph.confirmed_identity_claims = identity_candidate.confirmed_identity_claims;
        graph.anchored_canonical_identities = identity_candidate.anchored_canonical_identities;
        graph.revision = graph.revision.saturating_add(1);
        let receipt = GraphWriteReceipt {
            tenant_id: tenant_id.clone(),
            graph_revision: graph.revision,
            delta_digest,
            entities_upserted,
            assertions_upserted,
            assertions_retracted: retracted,
        };
        Ok(receipt)
    }

    fn validate_assertion_entities(
        current: Option<&TenantGraph>,
        incoming_entity_ids: &BTreeSet<&EntityId>,
        assertion: &GraphAssertion,
    ) -> Result<(), GraphError> {
        let endpoints: [&EntityId; 2] = match assertion {
            GraphAssertion::Relationship(value) => [value.from(), value.to()],
            GraphAssertion::IdentityBinding(value) => {
                [value.provider_identity(), value.canonical_identity()]
            }
        };
        for endpoint in endpoints {
            if !incoming_entity_ids.contains(endpoint)
                && !current.is_some_and(|graph| graph.entities.contains_key(endpoint))
            {
                return Err(GraphError::MissingEntity(endpoint.clone()));
            }
        }
        Ok(())
    }
}

impl TenantGraph {
    fn rebuild_identity_indexes(&mut self) -> Result<(), GraphError> {
        self.confirmed_identity_bindings.clear();
        self.confirmed_identity_claims.clear();
        self.anchored_canonical_identities.clear();

        let confirmed = self
            .assertions
            .values()
            .filter_map(|assertion| match assertion {
                GraphAssertion::IdentityBinding(binding)
                    if binding.state() == IdentityBindingState::Confirmed =>
                {
                    Some(binding.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        for binding in &confirmed {
            if let Some(existing) = self
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
            self.confirmed_identity_bindings.insert(
                binding.provider_identity().clone(),
                binding.canonical_identity().clone(),
            );
            if binding.method() == IdentityResolutionMethod::AuthoritativeEmployeeId {
                self.anchored_canonical_identities
                    .insert(binding.canonical_identity().clone());
                self.bind_claim(binding)?;
            }
        }

        for binding in &confirmed {
            match binding.method() {
                IdentityResolutionMethod::VerifiedEmail => {
                    if !self
                        .anchored_canonical_identities
                        .contains(binding.canonical_identity())
                    {
                        return Err(GraphError::CanonicalIdentityUnanchored(
                            binding.canonical_identity().clone(),
                        ));
                    }
                    self.bind_claim(binding)?;
                }
                IdentityResolutionMethod::HumanDecision => {
                    if binding.claim().is_some() {
                        self.bind_claim(binding)?;
                    }
                }
                IdentityResolutionMethod::AuthoritativeEmployeeId
                | IdentityResolutionMethod::ExistingClaimMatch
                | IdentityResolutionMethod::AgentProposal => {}
            }
        }

        for binding in &confirmed {
            if binding.method() != IdentityResolutionMethod::ExistingClaimMatch {
                continue;
            }
            let Some(claim) = binding.claim() else {
                return Err(GraphError::IdentityClaimNotFound {
                    claim_kind: IdentityClaimKind::VerifiedEmail,
                    claim_value: String::new(),
                    requested_canonical_identity: binding.canonical_identity().clone(),
                });
            };
            let key = (claim.kind(), claim.value().to_owned());
            if self.confirmed_identity_claims.get(&key) != Some(binding.canonical_identity()) {
                return Err(GraphError::IdentityClaimNotFound {
                    claim_kind: claim.kind(),
                    claim_value: claim.value().to_owned(),
                    requested_canonical_identity: binding.canonical_identity().clone(),
                });
            }
        }
        Ok(())
    }

    fn bind_claim(
        &mut self,
        binding: &cerebro_organizational_model::IdentityBindingAssertion,
    ) -> Result<(), GraphError> {
        let Some(claim) = binding.claim() else {
            return Ok(());
        };
        let key = (claim.kind(), claim.value().to_owned());
        if let Some(existing) = self.confirmed_identity_claims.get(&key)
            && existing != binding.canonical_identity()
        {
            return Err(GraphError::IdentityClaimAlreadyBound {
                claim_kind: claim.kind(),
                claim_value: claim.value().to_owned(),
                existing_canonical_identity: existing.clone(),
                requested_canonical_identity: binding.canonical_identity().clone(),
            });
        }
        self.confirmed_identity_claims
            .insert(key, binding.canonical_identity().clone());
        Ok(())
    }
}

/// Read-only organizational graph capability used by agents and product views.
///
/// Implementations return owned values so callers cannot mutate projection
/// state through a read handle.
pub trait GraphRead {
    /// Returns the current tenant revision, or zero when no tenant graph exists.
    fn graph_revision(&self, tenant_id: &TenantId) -> u64;
    /// Returns one entity from the tenant projection.
    fn entity(&self, tenant_id: &TenantId, entity_id: &EntityId) -> Option<Entity>;
    /// Returns all tenant entities in stable ID order.
    fn entities(&self, tenant_id: &TenantId) -> Vec<Entity>;
    /// Returns all tenant assertions in stable assertion-ID order.
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
        CompleteCollection, Entity, EntityKind, GraphAssertion, IdentityBindingAssertion,
        IdentityBindingState, IdentityClaim, IdentityClaimKind, IdentityResolutionMethod,
        ObservationId, ObservationRef, ProviderIdentity, ProviderKind, RelationKind,
        RelationshipAssertion, SourceRuntimeId,
    };

    use super::*;

    fn identity_delta(
        provider_id: &str,
        canonical_id: &str,
        state: IdentityBindingState,
        claim: Option<IdentityClaim>,
    ) -> GraphDelta {
        identity_delta_with_method(
            provider_id,
            canonical_id,
            IdentityResolutionMethod::HumanDecision,
            state,
            claim,
        )
    }

    fn identity_delta_with_method(
        provider_id: &str,
        canonical_id: &str,
        method: IdentityResolutionMethod,
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
            &provider, &canonical, method, claim, state, provenance, 10,
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

    fn workforce_delta(employee_id: &str, email: &str) -> (GraphDelta, CanonicalIdentity) {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let runtime = SourceRuntimeId::parse("okta-prod").unwrap();
        let collection = CompleteCollection::new(
            tenant.clone(),
            runtime.clone(),
            CollectionId::parse(format!("okta-{employee_id}")).unwrap(),
            "okta.users",
            10,
        )
        .unwrap();
        let provider = ProviderIdentity::new(
            tenant.clone(),
            runtime,
            ProviderKind::parse("okta.identity_user").unwrap(),
            "00u1",
            "Provider Person",
        )
        .unwrap();
        let employee_claim = IdentityClaim::employee_id(employee_id).unwrap();
        let canonical =
            CanonicalIdentity::for_claim(tenant, &employee_claim, "Canonical Person").unwrap();
        let provenance = AssertionProvenance::direct(
            vec![
                ObservationRef::new(
                    collection.receipt(),
                    ObservationId::parse(format!("observation-{employee_id}")).unwrap(),
                    "okta.user:00u1",
                )
                .unwrap(),
            ],
            "okta-identity-mapper",
            "v1",
        )
        .unwrap();
        let employee_binding = IdentityBindingAssertion::new(
            &provider,
            &canonical,
            IdentityResolutionMethod::AuthoritativeEmployeeId,
            Some(employee_claim),
            IdentityBindingState::Confirmed,
            provenance.clone(),
            10,
        )
        .unwrap();
        let email_binding = IdentityBindingAssertion::new(
            &provider,
            &canonical,
            IdentityResolutionMethod::VerifiedEmail,
            Some(IdentityClaim::verified_email(email).unwrap()),
            IdentityBindingState::Confirmed,
            provenance,
            10,
        )
        .unwrap();
        let mut builder = collection.begin_delta();
        builder.add_entity(provider.into_entity()).unwrap();
        builder.add_entity(canonical.clone().into_entity()).unwrap();
        builder
            .add_assertion(GraphAssertion::IdentityBinding(employee_binding))
            .unwrap();
        builder
            .add_assertion(GraphAssertion::IdentityBinding(email_binding))
            .unwrap();
        (builder.build(), canonical)
    }

    fn claim_match_delta(
        source: &str,
        provider_id: &str,
        email: &str,
        canonical: &CanonicalIdentity,
    ) -> GraphDelta {
        let runtime = SourceRuntimeId::parse(format!("{source}-prod")).unwrap();
        let collection = CompleteCollection::new(
            canonical.entity().tenant_id().clone(),
            runtime.clone(),
            CollectionId::parse(format!("{source}-{provider_id}")).unwrap(),
            format!("{source}.users"),
            20,
        )
        .unwrap();
        let provider = ProviderIdentity::new(
            canonical.entity().tenant_id().clone(),
            runtime,
            ProviderKind::parse(format!("{source}.identity_user")).unwrap(),
            provider_id,
            format!("{source} account"),
        )
        .unwrap();
        let provenance = AssertionProvenance::direct(
            vec![
                ObservationRef::new(
                    collection.receipt(),
                    ObservationId::parse(format!("observation-{source}-{provider_id}")).unwrap(),
                    format!("{source}.user:{provider_id}"),
                )
                .unwrap(),
            ],
            format!("{source}-identity-mapper"),
            "v1",
        )
        .unwrap();
        let binding = IdentityBindingAssertion::new(
            &provider,
            canonical,
            IdentityResolutionMethod::ExistingClaimMatch,
            Some(IdentityClaim::verified_email(email).unwrap()),
            IdentityBindingState::Confirmed,
            provenance,
            20,
        )
        .unwrap();
        let mut builder = collection.begin_delta();
        builder.add_entity(provider.into_entity()).unwrap();
        builder.add_entity(canonical.clone().into_entity()).unwrap();
        builder
            .add_assertion(GraphAssertion::IdentityBinding(binding))
            .unwrap();
        builder.build()
    }

    #[test]
    fn entity_conflict_is_rejected_without_partial_mutation() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let runtime = SourceRuntimeId::parse("okta-prod").unwrap();
        let provider = ProviderIdentity::new(
            tenant.clone(),
            runtime.clone(),
            ProviderKind::parse("okta.user").unwrap(),
            "00u-conflict",
            "Provider Person",
        )
        .unwrap()
        .into_entity();
        let conflicting = Entity::canonical(
            tenant.clone(),
            provider.id().clone(),
            EntityKind::Identity,
            "Canonical collision",
        )
        .unwrap();

        let mut graph = OrganizationalGraph::new();
        let mut first = CompleteCollection::new(
            tenant.clone(),
            runtime.clone(),
            CollectionId::parse("collection-conflict-first").unwrap(),
            "okta.users",
            10,
        )
        .unwrap()
        .begin_delta();
        first.add_entity(provider.clone()).unwrap();
        graph.apply(first.build()).unwrap();
        let revision = graph.graph_revision(&tenant);

        let mut second = CompleteCollection::new(
            tenant.clone(),
            runtime,
            CollectionId::parse("collection-conflict-second").unwrap(),
            "okta.users",
            10,
        )
        .unwrap()
        .begin_delta();
        second.add_entity(conflicting).unwrap();

        assert_eq!(
            graph.apply(second.build()),
            Err(GraphError::EntityConflict(provider.id().clone()))
        );
        assert_eq!(graph.graph_revision(&tenant), revision);
        assert_eq!(graph.entities(&tenant), vec![provider]);
        assert!(graph.assertions(&tenant).is_empty());
    }

    #[test]
    fn one_provider_identity_cannot_bind_to_two_canonical_identities() {
        let mut graph = OrganizationalGraph::new();
        let first = identity_delta("00u1", "person-1", IdentityBindingState::Confirmed, None);
        let (provider_identity, existing_canonical_identity) = match &first.assertions()[0] {
            GraphAssertion::IdentityBinding(binding) => (
                binding.provider_identity().clone(),
                binding.canonical_identity().clone(),
            ),
            _ => panic!("identity delta must contain an identity binding"),
        };
        graph.apply(first).unwrap();

        let second = identity_delta("00u1", "person-2", IdentityBindingState::Confirmed, None);
        let requested_canonical_identity = match &second.assertions()[0] {
            GraphAssertion::IdentityBinding(binding) => binding.canonical_identity().clone(),
            _ => panic!("identity delta must contain an identity binding"),
        };
        let revision = graph.graph_revision(&TenantId::parse("tenant-a").unwrap());

        assert_eq!(
            graph.apply(second),
            Err(GraphError::IdentityAlreadyBound {
                provider_identity,
                existing_canonical_identity,
                requested_canonical_identity,
            })
        );
        let tenant = TenantId::parse("tenant-a").unwrap();
        assert_eq!(graph.graph_revision(&tenant), revision);
        assert_eq!(graph.assertions(&tenant).len(), 1);
        assert_eq!(graph.entities(&tenant).len(), 2);
    }

    #[test]
    fn stable_entity_identity_allows_source_data_refresh() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let runtime = SourceRuntimeId::parse("okta-prod").unwrap();
        let entity = ProviderIdentity::new(
            tenant.clone(),
            runtime.clone(),
            ProviderKind::parse("okta.user").unwrap(),
            "00u-refresh",
            "Old label",
        )
        .unwrap()
        .into_entity();
        let refreshed = ProviderIdentity::new(
            tenant.clone(),
            runtime.clone(),
            ProviderKind::parse("okta.user").unwrap(),
            "00u-refresh",
            "New label",
        )
        .unwrap()
        .into_entity()
        .with_property("department", "Security")
        .unwrap();
        let mut graph = OrganizationalGraph::new();
        for (collection_id, value) in [
            ("collection-refresh-1", entity),
            ("collection-refresh-2", refreshed.clone()),
        ] {
            let collection = CompleteCollection::new(
                tenant.clone(),
                runtime.clone(),
                CollectionId::parse(collection_id).unwrap(),
                "okta.users",
                10,
            )
            .unwrap();
            let mut builder = collection.begin_delta();
            builder.add_entity(value).unwrap();
            graph.apply(builder.build()).unwrap();
        }
        assert_eq!(graph.entity(&tenant, refreshed.id()).unwrap(), refreshed);
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
        let claim_kind = IdentityClaimKind::EmployeeId;
        let claim_value = "employee-1".to_owned();
        let existing_canonical_identity = match &first.assertions()[0] {
            GraphAssertion::IdentityBinding(binding) => binding.canonical_identity().clone(),
            _ => panic!("identity delta must contain an identity binding"),
        };
        let second = identity_delta(
            "00u2",
            "person-2",
            IdentityBindingState::Confirmed,
            Some(IdentityClaim::employee_id("employee-1").unwrap()),
        );
        let requested_canonical_identity = match &second.assertions()[0] {
            GraphAssertion::IdentityBinding(binding) => binding.canonical_identity().clone(),
            _ => panic!("identity delta must contain an identity binding"),
        };
        graph.apply(first).unwrap();
        let revision = graph.graph_revision(&TenantId::parse("tenant-a").unwrap());
        assert_eq!(
            graph.apply(second),
            Err(GraphError::IdentityClaimAlreadyBound {
                claim_kind,
                claim_value,
                existing_canonical_identity,
                requested_canonical_identity,
            })
        );
        let tenant = TenantId::parse("tenant-a").unwrap();
        assert_eq!(graph.graph_revision(&tenant), revision);
        assert_eq!(graph.assertions(&tenant).len(), 1);
        assert_eq!(graph.entities(&tenant).len(), 2);
    }

    #[test]
    fn missing_assertion_entity_is_rejected_before_any_write() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let runtime = SourceRuntimeId::parse("okta-prod").unwrap();
        let collection = CompleteCollection::new(
            tenant.clone(),
            runtime.clone(),
            CollectionId::parse("collection-missing-entity").unwrap(),
            "okta.users",
            10,
        )
        .unwrap();
        let provider = ProviderIdentity::new(
            tenant.clone(),
            runtime,
            ProviderKind::parse("okta.user").unwrap(),
            "00u-missing",
            "Provider Person",
        )
        .unwrap()
        .into_entity();
        let repository = Entity::canonical(
            tenant,
            EntityId::parse("repository:missing").unwrap(),
            EntityKind::Repository,
            "Repository",
        )
        .unwrap();
        let provenance = AssertionProvenance::direct(
            vec![
                ObservationRef::new(
                    collection.receipt(),
                    ObservationId::parse("observation-missing-entity").unwrap(),
                    "okta.user:00u-missing",
                )
                .unwrap(),
            ],
            "okta-identity-mapper",
            "v1",
        )
        .unwrap();
        let relationship = RelationshipAssertion::new(
            &provider,
            RelationKind::CanAccess,
            &repository,
            provenance,
            10,
        )
        .unwrap();
        let mut builder = collection.begin_delta();
        builder
            .add_assertion(GraphAssertion::Relationship(relationship))
            .unwrap();

        let mut graph = OrganizationalGraph::new();
        assert_eq!(
            graph.apply(builder.build()),
            Err(GraphError::MissingEntity(provider.id().clone()))
        );
        assert_eq!(
            graph.graph_revision(&TenantId::parse("tenant-a").unwrap()),
            0
        );
        assert!(
            graph
                .entities(&TenantId::parse("tenant-a").unwrap())
                .is_empty()
        );
        assert!(
            graph
                .assertions(&TenantId::parse("tenant-a").unwrap())
                .is_empty()
        );
    }

    #[test]
    fn verified_email_binding_requires_an_authoritative_anchor() {
        let mut graph = OrganizationalGraph::new();
        let delta = identity_delta_with_method(
            "00u-unanchored",
            "person-unanchored",
            IdentityResolutionMethod::VerifiedEmail,
            IdentityBindingState::Confirmed,
            Some(IdentityClaim::verified_email("person@example.com").unwrap()),
        );
        let canonical_identity = match &delta.assertions()[0] {
            GraphAssertion::IdentityBinding(binding) => binding.canonical_identity().clone(),
            _ => panic!("identity delta must contain an identity binding"),
        };

        assert_eq!(
            graph.apply(delta),
            Err(GraphError::CanonicalIdentityUnanchored(canonical_identity))
        );
        let tenant = TenantId::parse("tenant-a").unwrap();
        assert_eq!(graph.graph_revision(&tenant), 0);
        assert!(graph.entities(&tenant).is_empty());
        assert!(graph.assertions(&tenant).is_empty());
    }

    #[test]
    fn existing_claim_match_requires_a_confirmed_claim() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let canonical = CanonicalIdentity::new(
            tenant,
            CanonicalIdentityId::parse("person-without-claim").unwrap(),
            "Canonical Person",
        )
        .unwrap();
        let delta = claim_match_delta(
            "github",
            "github-without-claim",
            "missing@example.com",
            &canonical,
        );
        let requested_canonical_identity = match &delta.assertions()[0] {
            GraphAssertion::IdentityBinding(binding) => binding.canonical_identity().clone(),
            _ => panic!("claim-match delta must contain an identity binding"),
        };
        let mut graph = OrganizationalGraph::new();

        assert_eq!(
            graph.apply(delta),
            Err(GraphError::IdentityClaimNotFound {
                claim_kind: IdentityClaimKind::VerifiedEmail,
                claim_value: "missing@example.com".to_owned(),
                requested_canonical_identity,
            })
        );
        assert_eq!(
            graph.graph_revision(&TenantId::parse("tenant-a").unwrap()),
            0
        );
    }

    #[test]
    fn retraction_from_another_runtime_is_rejected_without_removal() {
        let first = identity_delta(
            "00u-retract",
            "person-retract",
            IdentityBindingState::Confirmed,
            None,
        );
        let assertion_id = first.assertions()[0].id().clone();
        let tenant = TenantId::parse("tenant-a").unwrap();
        let mut graph = OrganizationalGraph::new();
        graph.apply(first).unwrap();
        let revision = graph.graph_revision(&tenant);

        let collection = CompleteCollection::new(
            tenant.clone(),
            SourceRuntimeId::parse("github-prod").unwrap(),
            CollectionId::parse("github-retract").unwrap(),
            "github.users",
            10,
        )
        .unwrap();
        let mut builder = collection.begin_delta();
        builder
            .retract_missing(assertion_id.clone(), "provider no longer reports it")
            .unwrap();

        assert_eq!(
            graph.apply(builder.build()),
            Err(GraphError::RetractionSourceMismatch(assertion_id))
        );
        assert_eq!(graph.graph_revision(&tenant), revision);
        assert_eq!(graph.assertions(&tenant).len(), 1);
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
        assert_eq!(
            graph.entities(&TenantId::parse("tenant-a").unwrap()).len(),
            2,
            "a rejected delta cannot insert its new canonical identity"
        );
    }

    #[test]
    fn workforce_claims_unify_okta_github_and_slack_accounts() {
        let mut graph = OrganizationalGraph::new();
        let (workforce, canonical) = workforce_delta("employee-1", "person@example.com");
        graph.apply(workforce).unwrap();
        graph
            .apply(claim_match_delta(
                "github",
                "github-1",
                "person@example.com",
                &canonical,
            ))
            .unwrap();
        graph
            .apply(claim_match_delta(
                "slack",
                "slack-1",
                "person@example.com",
                &canonical,
            ))
            .unwrap();
        let tenant = TenantId::parse("tenant-a").unwrap();
        assert_eq!(
            graph
                .entities(&tenant)
                .iter()
                .filter(|entity| entity.kind() == &cerebro_organizational_model::EntityKind::Person)
                .count(),
            1
        );
    }

    #[test]
    fn shared_alias_cannot_create_or_redirect_a_person() {
        let mut graph = OrganizationalGraph::new();
        let (workforce, canonical) = workforce_delta("employee-1", "person@example.com");
        graph.apply(workforce).unwrap();
        assert!(matches!(
            graph.apply(claim_match_delta(
                "slack",
                "slack-2",
                "shared@example.com",
                &canonical,
            )),
            Err(GraphError::IdentityClaimNotFound { .. })
        ));
    }

    #[test]
    fn non_directory_provider_cannot_seed_verified_email() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let runtime = SourceRuntimeId::parse("slack-prod").unwrap();
        let collection = CompleteCollection::new(
            tenant.clone(),
            runtime.clone(),
            CollectionId::parse("slack-user-1").unwrap(),
            "slack.users",
            10,
        )
        .unwrap();
        let provider = ProviderIdentity::new(
            tenant.clone(),
            runtime,
            ProviderKind::parse("slack.identity_user").unwrap(),
            "U1",
            "Slack account",
        )
        .unwrap();
        let employee_claim = IdentityClaim::employee_id("employee-1").unwrap();
        let canonical =
            CanonicalIdentity::for_claim(tenant, &employee_claim, "Canonical Person").unwrap();
        let provenance = AssertionProvenance::direct(
            vec![
                ObservationRef::new(
                    collection.receipt(),
                    ObservationId::parse("observation-slack-1").unwrap(),
                    "slack.user:U1",
                )
                .unwrap(),
            ],
            "slack-identity-mapper",
            "v1",
        )
        .unwrap();
        assert_eq!(
            IdentityBindingAssertion::new(
                &provider,
                &canonical,
                IdentityResolutionMethod::VerifiedEmail,
                Some(IdentityClaim::verified_email("person@example.com").unwrap()),
                IdentityBindingState::Confirmed,
                provenance,
                10,
            ),
            Err(cerebro_organizational_model::ModelError::InvalidIdentityBinding)
        );
    }
}
