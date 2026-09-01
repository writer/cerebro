//! Immutable context bindings and explicit later-observation outcomes.
//!
//! A binding content-addresses the exact context used by a task, mission,
//! decision, or action without introducing another snapshot model. It points
//! at the existing tenant graph revision and records the entity and assertion
//! digests whose change invalidates the bound work. The platform engine
//! evaluates later [`GraphDiff`] values produced from the durable graph ledger.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::{
    AssertionId, ContentDigest, ContextCoverageCompletenessV1, ContextFactV1, ContextSnapshotV1,
    EntityId, GraphChange, GraphDiff, GraphRevision, SdkError, TenantId,
};

const CONTEXT_BINDING_DIGEST_SCHEMA: &str = "cerebro.context-binding.v1";
const CONTEXT_EVALUATION_DIGEST_SCHEMA: &str = "cerebro.context-binding-evaluation.v1";
const MAX_CONTEXT_DEPENDENCIES: usize = 500;
const MAX_CONTEXT_REASON_CODES: usize = 32;
const MAX_CONTEXT_REASON_CODE_BYTES: usize = 128;

/// Stable graph target whose bound content participates in invalidation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum ContextDependencyTarget {
    /// Tenant-scoped organizational entity.
    Entity(EntityId),
    /// Tenant-scoped organizational assertion.
    Assertion(AssertionId),
}

/// Exact content digest of one dependency at the bound graph revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContextDependency {
    /// Stable entity or assertion identity.
    pub target: ContextDependencyTarget,
    /// Canonical content digest at [`ContextBinding::graph_revision`].
    pub content_digest: ContentDigest,
}

/// Immutable context consumed by later task, mission, decision, or action data.
///
/// Dependencies are sorted by target and unique. Their order is therefore a
/// canonical part of [`Self::binding_digest`] rather than caller-controlled
/// presentation order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContextBinding {
    /// Tenant that owns the graph revision and every dependency.
    pub tenant_id: TenantId,
    /// Exact non-zero graph revision used to assemble the context.
    pub graph_revision: GraphRevision,
    /// Digest of the complete canonical context supplied to the consumer.
    pub context_digest: ContentDigest,
    /// Exact entity and assertion content that can invalidate the context.
    pub dependencies: Vec<ContextDependency>,
    /// Schema-tagged digest of every preceding binding field.
    pub binding_digest: ContentDigest,
}

impl ContextBinding {
    /// Binds an already verified context snapshot to exact graph dependencies.
    ///
    /// The snapshot remains the sole context payload. This adapter converts its
    /// canonical digest and revision into the generic binding contract, and
    /// requires complete snapshot coverage and supplied dependencies for every
    /// entity and assertion referenced by its resolutions and facts. Extra
    /// dependencies are allowed when the snapshot assembler consumed additional
    /// graph records while resolving the bounded request.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Invalid`] when the snapshot cannot verify, is partial,
    /// has a non-canonical digest, or contains a referenced target that is not
    /// covered. Partial snapshots cannot be safely target-bound because a later
    /// record may resolve an earlier absence or ambiguity under a new identity.
    /// The usual [`Self::bind`] validation applies afterward.
    pub fn from_snapshot(
        snapshot: &ContextSnapshotV1,
        dependencies: Vec<ContextDependency>,
    ) -> Result<Self, SdkError> {
        snapshot
            .verify()
            .map_err(|_| SdkError::Invalid("context snapshot"))?;
        if snapshot.coverage().completeness() != ContextCoverageCompletenessV1::Complete {
            return Err(SdkError::Invalid("context snapshot completeness"));
        }
        let context_digest = snapshot
            .snapshot_digest()
            .strip_prefix("sha256:")
            .ok_or(SdkError::Invalid("context snapshot digest"))
            .and_then(ContentDigest::parse)?;
        let graph_revision = GraphRevision::new(snapshot.graph_revision())?;

        let supplied_targets = dependencies
            .iter()
            .map(|dependency| dependency.target.clone())
            .collect::<BTreeSet<_>>();
        let required_targets = snapshot_dependency_targets(snapshot);
        if !required_targets.is_subset(&supplied_targets) {
            return Err(SdkError::Invalid("context snapshot dependency coverage"));
        }

        Self::bind(
            snapshot.tenant_id().clone(),
            graph_revision,
            context_digest,
            dependencies,
        )
    }

    /// Constructs, canonicalizes, and content-addresses one context binding.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::OutOfRange`] unless there are `1..=500`
    /// dependencies, [`SdkError::Conflict`] when one target is repeated, or
    /// [`SdkError::Backend`] if canonical digest serialization fails.
    pub fn bind(
        tenant_id: TenantId,
        graph_revision: GraphRevision,
        context_digest: ContentDigest,
        mut dependencies: Vec<ContextDependency>,
    ) -> Result<Self, SdkError> {
        if dependencies.is_empty() || dependencies.len() > MAX_CONTEXT_DEPENDENCIES {
            return Err(SdkError::OutOfRange("context dependencies"));
        }
        dependencies.sort_by(|left, right| left.target.cmp(&right.target));
        if dependencies
            .windows(2)
            .any(|pair| pair[0].target == pair[1].target)
        {
            return Err(SdkError::Conflict(
                "duplicate context dependency target".to_owned(),
            ));
        }
        let mut binding = Self {
            tenant_id,
            graph_revision,
            context_digest,
            dependencies,
            binding_digest: ContentDigest::of_bytes([]),
        };
        binding.binding_digest = binding.computed_digest()?;
        Ok(binding)
    }

    /// Computes the schema-tagged digest of the binding's semantic fields.
    ///
    /// This method preserves stored dependency order. [`Self::validate`]
    /// separately requires canonical target order so reordered records cannot
    /// become alternate encodings of the same binding.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Backend`] if JSON serialization fails.
    pub fn computed_digest(&self) -> Result<ContentDigest, SdkError> {
        #[derive(Serialize)]
        struct DigestMaterial<'a> {
            schema: &'static str,
            tenant_id: &'a TenantId,
            graph_revision: GraphRevision,
            context_digest: &'a ContentDigest,
            dependencies: &'a [ContextDependency],
        }

        serde_json::to_vec(&DigestMaterial {
            schema: CONTEXT_BINDING_DIGEST_SCHEMA,
            tenant_id: &self.tenant_id,
            graph_revision: self.graph_revision,
            context_digest: &self.context_digest,
            dependencies: &self.dependencies,
        })
        .map(ContentDigest::of_bytes)
        .map_err(|error| {
            SdkError::Backend(format!("context binding serialization failed: {error}"))
        })
    }

    /// Validates dependency bounds, canonical order, uniqueness, and digest.
    ///
    /// This does not prove that the revision exists, that dependency digests
    /// match durable graph content, or that a caller may access the tenant.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::OutOfRange`] for an invalid dependency count,
    /// [`SdkError::Conflict`] for a repeated target, or [`SdkError::Invalid`]
    /// for non-canonical order or a mismatched binding digest.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.dependencies.is_empty() || self.dependencies.len() > MAX_CONTEXT_DEPENDENCIES {
            return Err(SdkError::OutOfRange("context dependencies"));
        }
        let mut seen = BTreeSet::new();
        for dependency in &self.dependencies {
            if !seen.insert(&dependency.target) {
                return Err(SdkError::Conflict(
                    "duplicate context dependency target".to_owned(),
                ));
            }
        }
        if self
            .dependencies
            .windows(2)
            .any(|pair| pair[0].target >= pair[1].target)
        {
            return Err(SdkError::Invalid("context dependency order"));
        }
        if self.binding_digest != self.computed_digest()? {
            return Err(SdkError::Invalid("context binding digest"));
        }
        Ok(())
    }
}

fn snapshot_dependency_targets(snapshot: &ContextSnapshotV1) -> BTreeSet<ContextDependencyTarget> {
    let mut targets = BTreeSet::new();
    for resolution in snapshot.subject_resolutions() {
        if let Some(person) = resolution.canonical_person() {
            targets.insert(ContextDependencyTarget::Entity(person.entity_id.clone()));
        }
        for candidate in resolution.candidates() {
            targets.insert(ContextDependencyTarget::Entity(candidate.entity_id.clone()));
        }
    }
    for contradiction in snapshot.contradictions() {
        for candidate in &contradiction.candidates {
            targets.insert(ContextDependencyTarget::Entity(candidate.entity_id.clone()));
        }
    }
    for fact in snapshot.facts() {
        match fact {
            ContextFactV1::CanonicalPerson { person } => {
                targets.insert(ContextDependencyTarget::Entity(person.entity_id.clone()));
            }
            ContextFactV1::IdentityBinding {
                person,
                provider_identity,
                assertion_id,
                ..
            } => {
                targets.insert(ContextDependencyTarget::Entity(person.entity_id.clone()));
                targets.insert(ContextDependencyTarget::Entity(
                    provider_identity.entity_id.clone(),
                ));
                targets.insert(ContextDependencyTarget::Assertion(assertion_id.clone()));
            }
            ContextFactV1::Access {
                person,
                target,
                path,
            } => {
                targets.insert(ContextDependencyTarget::Entity(person.entity_id.clone()));
                targets.insert(ContextDependencyTarget::Entity(target.entity_id.clone()));
                for edge in path {
                    targets.insert(ContextDependencyTarget::Entity(edge.from.entity_id.clone()));
                    targets.insert(ContextDependencyTarget::Entity(edge.to.entity_id.clone()));
                    targets.insert(ContextDependencyTarget::Assertion(
                        edge.assertion_id.clone(),
                    ));
                }
            }
        }
    }
    targets
}

/// Authority available for one later context observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextAuthorityState {
    /// Complete diff was assembled from the authoritative graph ledger.
    Authoritative,
    /// Some required records or pages were not available.
    Incomplete,
    /// The authoritative ledger or projection could not be read.
    Unavailable,
}

/// Later graph observation used to assess an immutable context binding.
///
/// This wrapper adds explicit authority/completeness state to the existing
/// temporal diff. It stores no entity or assertion snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContextObservation {
    /// Whether the diff is complete and authoritative.
    pub authority: ContextAuthorityState,
    /// Existing digest-bound temporal diff, when one could be assembled.
    pub diff: Option<GraphDiff>,
    /// Bounded machine-readable explanations for incomplete or unavailable data.
    pub reason_codes: Vec<String>,
}

impl ContextObservation {
    /// Validates authority/diff shape and bounded reason codes.
    ///
    /// Authoritative observations require a diff and no reason codes.
    /// Incomplete and unavailable observations require at least one reason.
    /// Diff integrity and binding checks are owned by the platform engine.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Invalid`] for an inconsistent authority shape or
    /// malformed reason, [`SdkError::OutOfRange`] for too many reasons, or
    /// [`SdkError::Conflict`] for duplicate reason codes.
    pub fn validate(&self) -> Result<(), SdkError> {
        match self.authority {
            ContextAuthorityState::Authoritative => {
                if self.diff.is_none() || !self.reason_codes.is_empty() {
                    return Err(SdkError::Invalid("context observation authority"));
                }
            }
            ContextAuthorityState::Incomplete | ContextAuthorityState::Unavailable => {
                if self.reason_codes.is_empty() {
                    return Err(SdkError::Invalid("context observation reasons"));
                }
            }
        }
        validate_reason_codes(&self.reason_codes)
    }
}

/// Deterministic relationship between a binding and a later observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextBindingState {
    /// Authoritative revision advanced without a graph content change.
    Unchanged,
    /// Authoritative graph content changed outside the bound dependencies.
    Changed,
    /// At least one exact bound dependency changed or was retracted.
    Invalidated,
    /// Authority or completeness was insufficient for a safe conclusion.
    Unknown,
}

/// Content-addressed result of evaluating one binding against later state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContextBindingEvaluation {
    /// Tenant shared by the binding and any accepted diff.
    pub tenant_id: TenantId,
    /// Digest of the immutable binding that was evaluated.
    pub binding_digest: ContentDigest,
    /// Exact graph revision used by the original context.
    pub bound_revision: GraphRevision,
    /// Later graph revision, when a diff was available.
    pub observed_revision: Option<GraphRevision>,
    /// Explicit semantic outcome.
    pub state: ContextBindingState,
    /// Digest of the complete temporal diff, when available.
    pub delta_digest: Option<ContentDigest>,
    /// Bound dependency changes proving invalidation or binding mismatch.
    pub dependency_changes: Vec<GraphChange>,
    /// Bounded reasons explaining an unknown outcome.
    pub reason_codes: Vec<String>,
    /// Schema-tagged canonical digest of the complete evaluation record.
    pub evaluation_digest: ContentDigest,
}

impl ContextBindingEvaluation {
    /// Computes the schema-tagged digest of the evaluation's semantic fields.
    ///
    /// Vector order is preserved. Callers should use [`Self::validate`] before
    /// treating the resulting digest as a verified outcome record.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Backend`] if JSON serialization fails.
    pub fn computed_digest(&self) -> Result<ContentDigest, SdkError> {
        #[derive(Serialize)]
        struct DigestMaterial<'a> {
            schema: &'static str,
            tenant_id: &'a TenantId,
            binding_digest: &'a ContentDigest,
            bound_revision: GraphRevision,
            observed_revision: Option<GraphRevision>,
            state: ContextBindingState,
            delta_digest: &'a Option<ContentDigest>,
            dependency_changes: &'a [GraphChange],
            reason_codes: &'a [String],
        }

        serde_json::to_vec(&DigestMaterial {
            schema: CONTEXT_EVALUATION_DIGEST_SCHEMA,
            tenant_id: &self.tenant_id,
            binding_digest: &self.binding_digest,
            bound_revision: self.bound_revision,
            observed_revision: self.observed_revision,
            state: self.state,
            delta_digest: &self.delta_digest,
            dependency_changes: &self.dependency_changes,
            reason_codes: &self.reason_codes,
        })
        .map(ContentDigest::of_bytes)
        .map_err(|error| {
            SdkError::Backend(format!(
                "context binding evaluation serialization failed: {error}"
            ))
        })
    }

    /// Replaces the stored digest with [`Self::computed_digest`].
    ///
    /// This helper does not call [`Self::validate`]; callers must validate the
    /// resulting evaluation before persisting or using it as evidence.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Backend`] if JSON serialization fails.
    pub fn bind_computed_digest(&mut self) -> Result<(), SdkError> {
        self.evaluation_digest = self.computed_digest()?;
        Ok(())
    }

    /// Validates outcome shape, canonical evidence ordering, and record digest.
    ///
    /// This verifies record integrity, not graph authority or whether the
    /// referenced binding and diff exist in durable storage.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Invalid`] for inconsistent outcome evidence or a
    /// mismatched digest, [`SdkError::OutOfRange`] for excessive evidence, or
    /// [`SdkError::Conflict`] for duplicate change targets or reason codes.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.observed_revision.is_some() != self.delta_digest.is_some() {
            return Err(SdkError::Invalid("context evaluation observation"));
        }
        if self
            .observed_revision
            .is_some_and(|revision| revision <= self.bound_revision)
        {
            return Err(SdkError::Invalid("context evaluation revision window"));
        }
        if !self.dependency_changes.is_empty() && self.observed_revision.is_none() {
            return Err(SdkError::Invalid("context evaluation observation"));
        }
        match self.state {
            ContextBindingState::Unchanged | ContextBindingState::Changed => {
                if self.observed_revision.is_none()
                    || !self.dependency_changes.is_empty()
                    || !self.reason_codes.is_empty()
                {
                    return Err(SdkError::Invalid("context evaluation evidence"));
                }
            }
            ContextBindingState::Invalidated => {
                if self.observed_revision.is_none()
                    || self.dependency_changes.is_empty()
                    || !self.reason_codes.is_empty()
                {
                    return Err(SdkError::Invalid("context evaluation evidence"));
                }
            }
            ContextBindingState::Unknown => {
                if self.reason_codes.is_empty() {
                    return Err(SdkError::Invalid("context evaluation reasons"));
                }
            }
        }
        if self.dependency_changes.len() > MAX_CONTEXT_DEPENDENCIES {
            return Err(SdkError::OutOfRange("context evaluation changes"));
        }
        let mut previous = None;
        for change in &self.dependency_changes {
            change.validate()?;
            let target = graph_change_target(change)
                .ok_or(SdkError::Invalid("context evaluation change target"))?;
            if previous.as_ref().is_some_and(|prior| prior == &target) {
                return Err(SdkError::Conflict(
                    "duplicate context evaluation change target".to_owned(),
                ));
            }
            if previous.as_ref().is_some_and(|prior| prior > &target) {
                return Err(SdkError::Invalid("context evaluation change order"));
            }
            previous = Some(target);
        }
        validate_reason_codes(&self.reason_codes)?;
        if self.evaluation_digest != self.computed_digest()? {
            return Err(SdkError::Invalid("context evaluation digest"));
        }
        Ok(())
    }
}

fn graph_change_target(change: &GraphChange) -> Option<ContextDependencyTarget> {
    match (&change.entity_id, &change.assertion_id) {
        (Some(entity_id), None) => Some(ContextDependencyTarget::Entity(entity_id.clone())),
        (None, Some(assertion_id)) => {
            Some(ContextDependencyTarget::Assertion(assertion_id.clone()))
        }
        _ => None,
    }
}

fn validate_reason_codes(reason_codes: &[String]) -> Result<(), SdkError> {
    if reason_codes.len() > MAX_CONTEXT_REASON_CODES {
        return Err(SdkError::OutOfRange("context observation reasons"));
    }
    let mut seen = BTreeSet::new();
    for reason in reason_codes {
        if reason.is_empty()
            || reason.len() > MAX_CONTEXT_REASON_CODE_BYTES
            || reason.trim() != reason
            || reason.chars().any(char::is_control)
            || !reason
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
        {
            return Err(SdkError::Invalid("context observation reason"));
        }
        if !seen.insert(reason) {
            return Err(SdkError::Conflict(
                "duplicate context observation reason".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use cerebro_organizational_graph::OrganizationalGraph;
    use cerebro_organizational_model::{
        CollectionId, CompleteCollection, Entity, EntityKind, SourceRuntimeId,
    };

    fn context_snapshot() -> ContextSnapshotV1 {
        let tenant = TenantId::parse("tenant-snapshot").unwrap();
        let person = Entity::canonical(
            tenant.clone(),
            EntityId::parse("person-1").unwrap(),
            EntityKind::Person,
            "Person One",
        )
        .unwrap();
        let collection = CompleteCollection::new(
            tenant.clone(),
            SourceRuntimeId::parse("runtime-1").unwrap(),
            CollectionId::parse("collection-1").unwrap(),
            "person",
            1,
        )
        .unwrap();
        let mut delta = collection.begin_delta();
        delta.add_entity(person).unwrap();
        let mut graph = OrganizationalGraph::new();
        graph.apply(delta.build()).unwrap();
        ContextSnapshotV1::capture(
            &graph,
            crate::ContextSnapshotRequestV1::new(
                tenant,
                vec![crate::ContextSelectorV1::canonical_person("person-1").unwrap()],
                10,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn snapshot_binding_uses_exact_snapshot_digest_and_requires_fact_coverage() {
        let snapshot = context_snapshot();
        let dependency = ContextDependency {
            target: ContextDependencyTarget::Entity(EntityId::parse("person-1").unwrap()),
            content_digest: ContentDigest::of_bytes("person-record"),
        };
        let binding = ContextBinding::from_snapshot(&snapshot, vec![dependency]).unwrap();

        assert_eq!(binding.tenant_id, snapshot.tenant_id().clone());
        assert_eq!(binding.graph_revision.get(), snapshot.graph_revision());
        assert_eq!(
            binding.context_digest.as_str(),
            snapshot.snapshot_digest().strip_prefix("sha256:").unwrap()
        );
        binding.validate().unwrap();

        assert_eq!(
            ContextBinding::from_snapshot(
                &snapshot,
                vec![ContextDependency {
                    target: ContextDependencyTarget::Entity(EntityId::parse("unrelated").unwrap()),
                    content_digest: ContentDigest::of_bytes("unrelated-record"),
                }],
            ),
            Err(SdkError::Invalid("context snapshot dependency coverage"))
        );
    }

    #[test]
    fn partial_snapshot_cannot_masquerade_as_dependency_complete() {
        let tenant = TenantId::parse("tenant-partial").unwrap();
        let snapshot = ContextSnapshotV1::capture(
            &OrganizationalGraph::new(),
            crate::ContextSnapshotRequestV1::new(
                tenant,
                vec![crate::ContextSelectorV1::canonical_person("missing-person").unwrap()],
                10,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            ContextBinding::from_snapshot(
                &snapshot,
                vec![ContextDependency {
                    target: ContextDependencyTarget::Entity(EntityId::parse("unrelated").unwrap()),
                    content_digest: ContentDigest::of_bytes("unrelated-record"),
                }],
            ),
            Err(SdkError::Invalid("context snapshot completeness"))
        );
    }

    #[test]
    fn binding_canonicalizes_dependencies_and_rejects_mutation() {
        let entity = ContextDependency {
            target: ContextDependencyTarget::Entity(EntityId::parse("entity-1").unwrap()),
            content_digest: ContentDigest::of_bytes("entity"),
        };
        let assertion = ContextDependency {
            target: ContextDependencyTarget::Assertion(AssertionId::parse("assertion-1").unwrap()),
            content_digest: ContentDigest::of_bytes("assertion"),
        };
        let mut binding = ContextBinding::bind(
            TenantId::parse("tenant-1").unwrap(),
            GraphRevision::new(7).unwrap(),
            ContentDigest::of_bytes("context"),
            vec![assertion, entity],
        )
        .unwrap();

        assert!(binding.validate().is_ok());
        assert!(matches!(
            binding.dependencies[0].target,
            ContextDependencyTarget::Entity(_)
        ));
        binding.context_digest = ContentDigest::of_bytes("changed");
        assert_eq!(
            binding.validate(),
            Err(SdkError::Invalid("context binding digest"))
        );

        let duplicate = ContextDependency {
            target: ContextDependencyTarget::Entity(EntityId::parse("entity-1").unwrap()),
            content_digest: ContentDigest::of_bytes("other"),
        };
        assert!(matches!(
            ContextBinding::bind(
                TenantId::parse("tenant-1").unwrap(),
                GraphRevision::new(7).unwrap(),
                ContentDigest::of_bytes("context"),
                vec![duplicate.clone(), duplicate],
            ),
            Err(SdkError::Conflict(_))
        ));
    }

    #[test]
    fn observations_require_explicit_authority_shape_and_bounded_reasons() {
        let unavailable = ContextObservation {
            authority: ContextAuthorityState::Unavailable,
            diff: None,
            reason_codes: vec!["graph_authority_unavailable".to_owned()],
        };
        assert!(unavailable.validate().is_ok());

        let invalid = ContextObservation {
            authority: ContextAuthorityState::Authoritative,
            diff: None,
            reason_codes: Vec::new(),
        };
        assert_eq!(
            invalid.validate(),
            Err(SdkError::Invalid("context observation authority"))
        );
    }

    #[test]
    fn evaluation_digest_detects_mutation() {
        let mut evaluation = ContextBindingEvaluation {
            tenant_id: TenantId::parse("tenant-1").unwrap(),
            binding_digest: ContentDigest::of_bytes("binding"),
            bound_revision: GraphRevision::new(7).unwrap(),
            observed_revision: Some(GraphRevision::new(8).unwrap()),
            state: ContextBindingState::Unchanged,
            delta_digest: Some(ContentDigest::of_bytes("delta")),
            dependency_changes: Vec::new(),
            reason_codes: Vec::new(),
            evaluation_digest: ContentDigest::of_bytes([]),
        };
        evaluation.bind_computed_digest().unwrap();
        assert!(evaluation.validate().is_ok());

        evaluation.state = ContextBindingState::Changed;
        assert_eq!(
            evaluation.validate(),
            Err(SdkError::Invalid("context evaluation digest"))
        );
    }
}
