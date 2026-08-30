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
/// Private current-state material for one tenant projection.
///
/// The assertion map is authoritative for the three derived identity indexes;
/// those indexes are rebuilt together whenever assertions change. Ordered maps
/// make read order and conflict discovery deterministic.
struct TenantGraph {
    /// Saturating in-memory accepted-write revision.
    revision: u64,
    /// Current entities keyed by stable identity.
    entities: BTreeMap<EntityId, Entity>,
    /// Current assertions keyed by deterministic assertion identity.
    assertions: BTreeMap<AssertionId, GraphAssertion>,
    /// Confirmed provider identity to canonical identity mapping.
    confirmed_identity_bindings: BTreeMap<EntityId, EntityId>,
    /// Confirmed normalized claim to canonical identity mapping.
    confirmed_identity_claims: BTreeMap<(IdentityClaimKind, String), EntityId>,
    /// Canonical identities backed by authoritative employee-ID evidence.
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

    /// Applies a sealed-model delta atomically to one tenant's current projection.
    ///
    /// Entity-only deltas validate stable identity and update entities directly.
    /// Deltas containing assertion upserts or retractions build a complete
    /// candidate assertion map, validate endpoint existence and retraction
    /// ownership, rebuild every identity index, and only then replace current
    /// assertion state. Entities are upserted but never removed by this method.
    ///
    /// Missing retraction targets are idempotent no-ops and are not counted in the
    /// receipt. Counts reflect submitted upserts and actual removals, not semantic
    /// changes from prior values. Every accepted delta advances the in-memory
    /// revision with saturating arithmetic; revision overflow remains pinned at
    /// `u64::MAX` rather than returning an error.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::EntityConflict`] for stable-identity drift,
    /// [`GraphError::MissingEntity`] for an assertion with an absent endpoint,
    /// [`GraphError::RetractionSourceMismatch`] for a cross-runtime retraction,
    /// or an identity-index conflict. No tenant state is mutated on error.
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
            // The identity indexes depend only on assertions, so an entity-only
            // delta can commit without rebuilding them.
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
            // Missing targets are replay-safe no-ops; a receipt counts only
            // assertions that were present and actually removed.
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

        // Saturation keeps this in-memory projection total, but persistence must
        // treat a pinned maximum revision as an operational exhaustion state.
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

    /// Requires both assertion endpoints in current or same-delta entity state.
    fn validate_assertion_entities(
        current: Option<&TenantGraph>,
        incoming_entity_ids: &BTreeSet<&EntityId>,
        assertion: &GraphAssertion,
    ) -> Result<(), GraphError> {
        // Both relationship and identity-binding assertions have exactly two
        // entity endpoints, allowing one closed existence rule for both families.
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
    /// Reconstructs all confirmed identity indexes from candidate assertions.
    ///
    /// Processing occurs in three passes. First, every confirmed provider
    /// identity is bound to at most one canonical identity and authoritative
    /// employee-ID bindings establish anchors and any supplied claims. Second,
    /// verified-email claims require an existing authoritative anchor while human
    /// decisions may contribute an explicit claim. Third, existing-claim matches
    /// must resolve to a claim established by an earlier pass for the same canonical identity.
    ///
    /// Agent proposals do not establish anchors or claims. Proposed/rejected
    /// bindings are excluded entirely. Indexes are cleared before rebuilding, so
    /// callers must use this method only on a private candidate graph.
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

        // Provider identities are unique across all confirmed methods. The
        // authoritative method also seeds canonical anchors before email checks.
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

        // Verified email may strengthen only an already anchored canonical
        // identity; a human decision may introduce an explicit reviewed claim.
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

        // Existing-claim matching consumes, but never creates, claim authority.
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

    /// Adds an optional normalized claim with one-canonical-identity semantics.
    ///
    /// Repeating the same claim-to-identity binding is idempotent. Reusing the
    /// claim for another canonical identity fails the entire candidate rebuild.
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
mod tests;
