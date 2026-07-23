#![forbid(unsafe_code)]

//! Rust-owned admission and current-state graph engine.

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
    CanonicalIdentityUnanchored(EntityId),
    IdentityClaimNotFound {
        claim_kind: IdentityClaimKind,
        claim_value: String,
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
    anchored_canonical_identities: BTreeSet<EntityId>,
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
        let (collection, entities, assertions, retractions, delta_digest) = delta.into_components();
        let tenant_id = collection.tenant_id().clone();
        let entities_upserted = entities.len();
        let assertions_upserted = assertions.len();
        let mut candidate = self.tenants.get(&tenant_id).cloned().unwrap_or_default();

        for entity in entities {
            if let Some(existing) = candidate.entities.get(entity.id())
                && !existing.has_same_identity(&entity)
            {
                return Err(GraphError::EntityConflict(entity.id().clone()));
            }
            candidate.entities.insert(entity.id().clone(), entity);
        }

        for assertion in assertions {
            self.validate_assertion_entities(&candidate, &assertion)?;
            candidate
                .assertions
                .insert(assertion.id().clone(), assertion);
        }

        let mut retracted = 0;
        for retraction in retractions {
            if let Some(assertion) = candidate.assertions.get(retraction.assertion_id()) {
                if assertion.provenance().source_runtime_id() != collection.source_runtime_id() {
                    return Err(GraphError::RetractionSourceMismatch(
                        retraction.assertion_id().clone(),
                    ));
                }
                candidate.assertions.remove(retraction.assertion_id());
                retracted += 1;
            }
        }
        candidate.rebuild_identity_indexes()?;

        candidate.revision = candidate.revision.saturating_add(1);
        let receipt = GraphWriteReceipt {
            tenant_id: tenant_id.clone(),
            graph_revision: candidate.revision,
            delta_digest,
            entities_upserted,
            assertions_upserted,
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
