//! Immutable, revision-bound security context snapshots for agent decisions.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use cerebro_organizational_graph::GraphRead;
use cerebro_organizational_model::{
    AssertionId, Entity, EntityId, EntityKind, GraphAssertion, IdentityBindingState, RelationKind,
    SourceRuntimeId, TenantId,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Stable schema identifier for the first agent security context snapshot.
pub const CONTEXT_SNAPSHOT_SCHEMA_V1: &str = "cerebro.context-snapshot.v1";

const MAX_SELECTORS: usize = 100;
const MAX_FACTS: usize = 500;
const MAX_SELECTOR_KEY_BYTES: usize = 512;
const MAX_AMBIGUITY_CANDIDATES: usize = 20;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Rejection produced while validating or assembling a context snapshot.
pub enum SnapshotError {
    /// One request field violates the bounded snapshot contract.
    Invalid(&'static str),
    /// The graph revision changed while the snapshot was being assembled.
    RevisionChanged {
        /// Revision read before graph materialization.
        before: u64,
        /// Revision read after graph materialization.
        after: u64,
    },
    /// Canonical serialization failed for a validated snapshot value.
    Canonicalization,
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(field) => write!(formatter, "invalid context snapshot {field}"),
            Self::RevisionChanged { before, after } => write!(
                formatter,
                "context graph revision changed during capture ({before} to {after})"
            ),
            Self::Canonicalization => {
                formatter.write_str("context snapshot canonicalization failed")
            }
        }
    }
}

impl Error for SnapshotError {}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// Closed selector vocabulary admitted by [`ContextSnapshotRequestV1`].
pub enum ContextSelectorV1 {
    /// Resolve one canonical person by an exact stable entity ID or agent key.
    CanonicalPerson {
        /// Exact, normalized stable key supplied by the caller.
        key: String,
    },
    /// Resolve one canonical person and collect bounded access facts for it.
    Access {
        /// Exact, normalized stable key of the canonical person.
        person_key: String,
    },
}

impl ContextSelectorV1 {
    /// Constructs a canonical-person selector from an exact stable key.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::Invalid`] when the key is empty, padded,
    /// control-bearing, or longer than 512 bytes.
    pub fn canonical_person(key: impl Into<String>) -> Result<Self, SnapshotError> {
        Ok(Self::CanonicalPerson {
            key: validate_selector_key(key.into())?,
        })
    }

    /// Constructs an access selector from an exact canonical-person key.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::Invalid`] when the key is empty, padded,
    /// control-bearing, or longer than 512 bytes.
    pub fn access(person_key: impl Into<String>) -> Result<Self, SnapshotError> {
        Ok(Self::Access {
            person_key: validate_selector_key(person_key.into())?,
        })
    }

    fn key(&self) -> &str {
        match self {
            Self::CanonicalPerson { key } => key,
            Self::Access { person_key } => person_key,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Validated request for one immutable tenant-scoped context snapshot.
pub struct ContextSnapshotRequestV1 {
    tenant_id: TenantId,
    selectors: Vec<ContextSelectorV1>,
    max_facts: usize,
}

impl ContextSnapshotRequestV1 {
    /// Validates a tenant, closed selector list, and fact ceiling.
    ///
    /// Selectors are sorted into canonical order and duplicates are rejected.
    /// The request accepts between one and 100 selectors and between one and
    /// 500 output facts.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::Invalid`] for an empty, duplicate, or over-bound
    /// selector set or for an invalid fact ceiling.
    pub fn new(
        tenant_id: TenantId,
        mut selectors: Vec<ContextSelectorV1>,
        max_facts: usize,
    ) -> Result<Self, SnapshotError> {
        if selectors.is_empty() || selectors.len() > MAX_SELECTORS {
            return Err(SnapshotError::Invalid("selector count"));
        }
        if !(1..=MAX_FACTS).contains(&max_facts) {
            return Err(SnapshotError::Invalid("fact limit"));
        }
        selectors.sort();
        if selectors.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(SnapshotError::Invalid("duplicate selector"));
        }
        Ok(Self {
            tenant_id,
            selectors,
            max_facts,
        })
    }

    /// Returns the tenant whose graph may satisfy every selector.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the canonically ordered selector set.
    pub fn selectors(&self) -> &[ContextSelectorV1] {
        &self.selectors
    }

    /// Returns the hard maximum number of facts in the snapshot.
    pub fn max_facts(&self) -> usize {
        self.max_facts
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
/// Secret-free stable reference to one resolved graph subject.
pub struct ContextSubjectRefV1 {
    /// Tenant-local stable entity identity.
    pub entity_id: EntityId,
    /// Closed organizational entity kind.
    pub entity_kind: EntityKind,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
/// Outcome of resolving one context selector.
pub enum ContextSubjectResolutionStateV1 {
    /// Exactly one canonical person satisfied the selector.
    Resolved,
    /// More than one canonical person satisfied the selector.
    Ambiguous,
    /// No canonical person satisfied the selector.
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Bounded resolution outcome for one requested subject.
pub struct ContextSubjectResolutionV1 {
    selector: ContextSelectorV1,
    state: ContextSubjectResolutionStateV1,
    canonical_person: Option<ContextSubjectRefV1>,
    candidates: Vec<ContextSubjectRefV1>,
    candidate_count: usize,
    candidates_truncated: bool,
}

impl ContextSubjectResolutionV1 {
    /// Returns the exact selector whose outcome is recorded.
    pub fn selector(&self) -> &ContextSelectorV1 {
        &self.selector
    }

    /// Returns the explicit resolution state.
    pub fn state(&self) -> ContextSubjectResolutionStateV1 {
        self.state
    }

    /// Returns the one resolved canonical person, when unambiguous.
    pub fn canonical_person(&self) -> Option<&ContextSubjectRefV1> {
        self.canonical_person.as_ref()
    }

    /// Returns at most 20 deterministic ambiguity candidates.
    pub fn candidates(&self) -> &[ContextSubjectRefV1] {
        &self.candidates
    }

    /// Returns the full candidate count before the display bound was applied.
    pub fn candidate_count(&self) -> usize {
        self.candidate_count
    }

    /// Returns whether additional ambiguity candidates were omitted.
    pub fn candidates_truncated(&self) -> bool {
        self.candidates_truncated
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
/// One evidence-backed edge in an access path.
pub struct ContextAccessEdgeV1 {
    /// Stable assertion identity.
    pub assertion_id: AssertionId,
    /// Stable source endpoint.
    pub from: ContextSubjectRefV1,
    /// Closed organizational relation name.
    pub relation: RelationKind,
    /// Stable destination endpoint.
    pub to: ContextSubjectRefV1,
    /// Source runtime whose admitted evidence supports the edge.
    pub source_runtime_id: SourceRuntimeId,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// Secret-free security fact captured at one graph revision.
pub enum ContextFactV1 {
    /// The selector resolved to one canonical person.
    CanonicalPerson {
        /// Resolved canonical person.
        person: ContextSubjectRefV1,
    },
    /// A confirmed provider identity represents the canonical person.
    IdentityBinding {
        /// Resolved canonical person.
        person: ContextSubjectRefV1,
        /// Confirmed provider-owned identity.
        provider_identity: ContextSubjectRefV1,
        /// Stable identity-binding assertion ID.
        assertion_id: AssertionId,
        /// Source runtime whose evidence supports the binding.
        source_runtime_id: SourceRuntimeId,
    },
    /// A direct or one-intermediate-hop access path from the person.
    Access {
        /// Resolved canonical person anchoring the path.
        person: ContextSubjectRefV1,
        /// Resource, account, role, environment, application, or service reached.
        target: ContextSubjectRefV1,
        /// One or two ordered evidence-backed access edges.
        path: Vec<ContextAccessEdgeV1>,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
/// Closed contradiction classes emitted by the first resolver vertical.
pub enum ContextContradictionKindV1 {
    /// One stable key matched more than one canonical person.
    AmbiguousCanonicalPerson,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
/// Bounded contradiction retained instead of guessing a subject.
pub struct ContextContradictionV1 {
    /// Selector whose resolution contradicted uniqueness.
    pub selector: ContextSelectorV1,
    /// Typed contradiction class.
    pub kind: ContextContradictionKindV1,
    /// At most 20 stable conflicting candidates.
    pub candidates: Vec<ContextSubjectRefV1>,
    /// Full candidate count before the display bound was applied.
    pub candidate_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
/// Closed unknown classes emitted by the first resolver vertical.
pub enum ContextUnknownReasonV1 {
    /// No canonical person matched the supplied stable key.
    CanonicalPersonNotFound,
    /// A person resolved but no admitted access path was observed.
    AccessNotObserved,
    /// The fact ceiling omitted one or more deterministic facts.
    FactLimitReached,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
/// Explicit unknown retained in the snapshot instead of inferred as false.
pub struct ContextUnknownV1 {
    /// Selector to which this unknown applies, or `None` for a snapshot-wide bound.
    pub selector: Option<ContextSelectorV1>,
    /// Typed unknown reason.
    pub reason: ContextUnknownReasonV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Whether the snapshot fully answered its bounded request.
pub enum ContextCoverageCompletenessV1 {
    /// Every selector resolved and the fact ceiling omitted nothing.
    Complete,
    /// At least one selector was ambiguous, unknown, or fact-truncated.
    Partial,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Aggregate coverage statement for one context snapshot.
pub struct ContextCoverageV1 {
    requested_selectors: usize,
    resolved_selectors: usize,
    ambiguous_selectors: usize,
    unknown_selectors: usize,
    fact_count: usize,
    contradiction_count: usize,
    unknown_count: usize,
    facts_truncated: bool,
    completeness: ContextCoverageCompletenessV1,
}

impl ContextCoverageV1 {
    /// Returns the number of requested selectors.
    pub fn requested_selectors(&self) -> usize {
        self.requested_selectors
    }

    /// Returns the number of selectors resolved to one person.
    pub fn resolved_selectors(&self) -> usize {
        self.resolved_selectors
    }

    /// Returns the number of explicitly ambiguous selectors.
    pub fn ambiguous_selectors(&self) -> usize {
        self.ambiguous_selectors
    }

    /// Returns the number of selectors with no matching person.
    pub fn unknown_selectors(&self) -> usize {
        self.unknown_selectors
    }

    /// Returns the bounded number of retained facts.
    pub fn fact_count(&self) -> usize {
        self.fact_count
    }

    /// Returns the number of retained contradictions.
    pub fn contradiction_count(&self) -> usize {
        self.contradiction_count
    }

    /// Returns the number of retained explicit unknowns.
    pub fn unknown_count(&self) -> usize {
        self.unknown_count
    }

    /// Returns whether the fact limit omitted one or more facts.
    pub fn facts_truncated(&self) -> bool {
        self.facts_truncated
    }

    /// Returns the complete or partial coverage classification.
    pub fn completeness(&self) -> ContextCoverageCompletenessV1 {
        self.completeness
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Immutable, tenant-scoped security context bound to one graph revision.
pub struct ContextSnapshotV1 {
    schema: &'static str,
    snapshot_id: String,
    tenant_id: TenantId,
    graph_revision: u64,
    request_digest: String,
    subject_resolutions: Vec<ContextSubjectResolutionV1>,
    facts: Vec<ContextFactV1>,
    coverage: ContextCoverageV1,
    contradictions: Vec<ContextContradictionV1>,
    unknowns: Vec<ContextUnknownV1>,
    snapshot_digest: String,
}

impl ContextSnapshotV1 {
    /// Resolves the request against one stable [`GraphRead`] revision.
    ///
    /// The current production vertical resolves exact canonical-person keys and
    /// direct or one-intermediate-hop access facts. Every output collection is
    /// deterministically ordered, the fact set is hard-bounded, and entity
    /// presentation properties are never copied into the snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::RevisionChanged`] if the graph changes during
    /// capture or [`SnapshotError::Canonicalization`] if canonical digesting fails.
    pub fn capture<Reader: GraphRead>(
        reader: &Reader,
        request: ContextSnapshotRequestV1,
    ) -> Result<Self, SnapshotError> {
        let request_digest = canonical_digest(&request)?;
        let before = reader.graph_revision(request.tenant_id());
        let mut entities = reader.entities(request.tenant_id());
        let mut assertions = reader.assertions(request.tenant_id());
        let after = reader.graph_revision(request.tenant_id());
        if before != after {
            return Err(SnapshotError::RevisionChanged { before, after });
        }
        entities.sort_by(|left, right| left.id().cmp(right.id()));
        assertions.sort_by(|left, right| left.id().cmp(right.id()));
        let entities_by_id = entities
            .iter()
            .map(|entity| (entity.id().clone(), entity))
            .collect::<BTreeMap<_, _>>();

        let mut subject_resolutions = Vec::with_capacity(request.selectors.len());
        let mut facts = BTreeSet::new();
        let mut contradictions = BTreeSet::new();
        let mut unknowns = BTreeSet::new();
        let mut facts_truncated = false;

        for selector in &request.selectors {
            let mut candidates = entities
                .iter()
                .filter(|entity| {
                    entity.kind() == &EntityKind::Person
                        && (entity.id().as_str() == selector.key()
                            || entity.agent_key() == selector.key())
                })
                .map(subject_ref)
                .collect::<Vec<_>>();
            candidates.sort();
            let candidate_count = candidates.len();
            let candidates_truncated = candidate_count > MAX_AMBIGUITY_CANDIDATES;
            candidates.truncate(MAX_AMBIGUITY_CANDIDATES);

            match candidate_count {
                0 => {
                    unknowns.insert(ContextUnknownV1 {
                        selector: Some(selector.clone()),
                        reason: ContextUnknownReasonV1::CanonicalPersonNotFound,
                    });
                    subject_resolutions.push(ContextSubjectResolutionV1 {
                        selector: selector.clone(),
                        state: ContextSubjectResolutionStateV1::Unknown,
                        canonical_person: None,
                        candidates: Vec::new(),
                        candidate_count: 0,
                        candidates_truncated: false,
                    });
                }
                1 => {
                    let person = candidates[0].clone();
                    insert_bounded(
                        &mut facts,
                        ContextFactV1::CanonicalPerson {
                            person: person.clone(),
                        },
                        request.max_facts,
                        &mut facts_truncated,
                    );
                    if matches!(selector, ContextSelectorV1::Access { .. }) {
                        let access_observed = collect_access_facts(
                            &person,
                            &entities_by_id,
                            &assertions,
                            &mut facts,
                            request.max_facts,
                            &mut facts_truncated,
                        );
                        if !access_observed {
                            unknowns.insert(ContextUnknownV1 {
                                selector: Some(selector.clone()),
                                reason: ContextUnknownReasonV1::AccessNotObserved,
                            });
                        }
                    }
                    subject_resolutions.push(ContextSubjectResolutionV1 {
                        selector: selector.clone(),
                        state: ContextSubjectResolutionStateV1::Resolved,
                        canonical_person: Some(person),
                        candidates: Vec::new(),
                        candidate_count: 1,
                        candidates_truncated: false,
                    });
                }
                _ => {
                    contradictions.insert(ContextContradictionV1 {
                        selector: selector.clone(),
                        kind: ContextContradictionKindV1::AmbiguousCanonicalPerson,
                        candidates: candidates.clone(),
                        candidate_count,
                    });
                    subject_resolutions.push(ContextSubjectResolutionV1 {
                        selector: selector.clone(),
                        state: ContextSubjectResolutionStateV1::Ambiguous,
                        canonical_person: None,
                        candidates,
                        candidate_count,
                        candidates_truncated,
                    });
                }
            }
        }

        if facts_truncated {
            unknowns.insert(ContextUnknownV1 {
                selector: None,
                reason: ContextUnknownReasonV1::FactLimitReached,
            });
        }
        let facts = facts.into_iter().collect::<Vec<_>>();
        let contradictions = contradictions.into_iter().collect::<Vec<_>>();
        let unknowns = unknowns.into_iter().collect::<Vec<_>>();
        let resolved_selectors = subject_resolutions
            .iter()
            .filter(|resolution| resolution.state == ContextSubjectResolutionStateV1::Resolved)
            .count();
        let ambiguous_selectors = subject_resolutions
            .iter()
            .filter(|resolution| resolution.state == ContextSubjectResolutionStateV1::Ambiguous)
            .count();
        let unknown_selectors = subject_resolutions
            .iter()
            .filter(|resolution| resolution.state == ContextSubjectResolutionStateV1::Unknown)
            .count();
        let complete = ambiguous_selectors == 0
            && unknown_selectors == 0
            && !facts_truncated
            && !unknowns
                .iter()
                .any(|unknown| unknown.reason == ContextUnknownReasonV1::AccessNotObserved);
        let coverage = ContextCoverageV1 {
            requested_selectors: request.selectors.len(),
            resolved_selectors,
            ambiguous_selectors,
            unknown_selectors,
            fact_count: facts.len(),
            contradiction_count: contradictions.len(),
            unknown_count: unknowns.len(),
            facts_truncated,
            completeness: if complete {
                ContextCoverageCompletenessV1::Complete
            } else {
                ContextCoverageCompletenessV1::Partial
            },
        };
        let canonical = ContextSnapshotCanonicalV1 {
            schema: CONTEXT_SNAPSHOT_SCHEMA_V1,
            tenant_id: request.tenant_id(),
            graph_revision: before,
            request_digest: &request_digest,
            subject_resolutions: &subject_resolutions,
            facts: &facts,
            coverage: &coverage,
            contradictions: &contradictions,
            unknowns: &unknowns,
        };
        let snapshot_digest = canonical_digest(&canonical)?;
        let snapshot_id = format!(
            "context-snapshot:{}",
            snapshot_digest
                .strip_prefix("sha256:")
                .expect("canonical digests always use the sha256 prefix")
        );
        Ok(Self {
            schema: CONTEXT_SNAPSHOT_SCHEMA_V1,
            snapshot_id,
            tenant_id: request.tenant_id,
            graph_revision: before,
            request_digest,
            subject_resolutions,
            facts,
            coverage,
            contradictions,
            unknowns,
            snapshot_digest,
        })
    }

    /// Returns the stable schema identifier.
    pub fn schema(&self) -> &str {
        self.schema
    }

    /// Returns the content-addressed snapshot identity.
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    /// Returns the tenant that owns every resolution and fact.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the exact graph revision captured by this snapshot.
    pub fn graph_revision(&self) -> u64 {
        self.graph_revision
    }

    /// Returns the deterministic digest of the normalized request.
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    /// Returns the deterministic subject-resolution outcomes.
    pub fn subject_resolutions(&self) -> &[ContextSubjectResolutionV1] {
        &self.subject_resolutions
    }

    /// Returns the bounded, deterministic security facts.
    pub fn facts(&self) -> &[ContextFactV1] {
        &self.facts
    }

    /// Returns the aggregate coverage statement.
    pub fn coverage(&self) -> &ContextCoverageV1 {
        &self.coverage
    }

    /// Returns explicit bounded contradictions.
    pub fn contradictions(&self) -> &[ContextContradictionV1] {
        &self.contradictions
    }

    /// Returns explicit bounded unknowns.
    pub fn unknowns(&self) -> &[ContextUnknownV1] {
        &self.unknowns
    }

    /// Returns the deterministic digest of all preceding snapshot fields.
    pub fn snapshot_digest(&self) -> &str {
        &self.snapshot_digest
    }

    /// Recomputes and verifies the content digest and content-addressed ID.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::Canonicalization`] if canonical serialization
    /// fails or [`SnapshotError::Invalid`] when stored identity does not match.
    pub fn verify(&self) -> Result<(), SnapshotError> {
        let canonical = ContextSnapshotCanonicalV1 {
            schema: self.schema,
            tenant_id: &self.tenant_id,
            graph_revision: self.graph_revision,
            request_digest: &self.request_digest,
            subject_resolutions: &self.subject_resolutions,
            facts: &self.facts,
            coverage: &self.coverage,
            contradictions: &self.contradictions,
            unknowns: &self.unknowns,
        };
        let digest = canonical_digest(&canonical)?;
        let expected_id = format!(
            "context-snapshot:{}",
            digest
                .strip_prefix("sha256:")
                .expect("canonical digests always use the sha256 prefix")
        );
        if digest != self.snapshot_digest || expected_id != self.snapshot_id {
            return Err(SnapshotError::Invalid("digest"));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ContextSnapshotCanonicalV1<'a> {
    schema: &'a str,
    tenant_id: &'a TenantId,
    graph_revision: u64,
    request_digest: &'a str,
    subject_resolutions: &'a [ContextSubjectResolutionV1],
    facts: &'a [ContextFactV1],
    coverage: &'a ContextCoverageV1,
    contradictions: &'a [ContextContradictionV1],
    unknowns: &'a [ContextUnknownV1],
}

fn collect_access_facts(
    person: &ContextSubjectRefV1,
    entities: &BTreeMap<EntityId, &Entity>,
    assertions: &[GraphAssertion],
    facts: &mut BTreeSet<ContextFactV1>,
    max_facts: usize,
    truncated: &mut bool,
) -> bool {
    let mut access_observed = false;
    let mut roots = BTreeSet::from([person.entity_id.clone()]);
    for assertion in assertions {
        let GraphAssertion::IdentityBinding(binding) = assertion else {
            continue;
        };
        if binding.state() != IdentityBindingState::Confirmed
            || binding.canonical_identity() != &person.entity_id
        {
            continue;
        }
        let Some(identity) = entities.get(binding.provider_identity()) else {
            continue;
        };
        let identity = subject_ref(identity);
        roots.insert(identity.entity_id.clone());
        insert_bounded(
            facts,
            ContextFactV1::IdentityBinding {
                person: person.clone(),
                provider_identity: identity,
                assertion_id: binding.id().clone(),
                source_runtime_id: binding.provenance().source_runtime_id().clone(),
            },
            max_facts,
            truncated,
        );
    }

    let relationships = assertions
        .iter()
        .filter_map(|assertion| match assertion {
            GraphAssertion::Relationship(relationship) => Some(relationship),
            GraphAssertion::IdentityBinding(_) => None,
        })
        .collect::<Vec<_>>();
    for relationship in &relationships {
        if !roots.contains(relationship.from()) {
            continue;
        }
        if is_terminal_access(relationship.relation()) {
            if let Some(edge) = access_edge(relationship, entities) {
                access_observed = true;
                insert_bounded(
                    facts,
                    ContextFactV1::Access {
                        person: person.clone(),
                        target: edge.to.clone(),
                        path: vec![edge],
                    },
                    max_facts,
                    truncated,
                );
            }
            continue;
        }
        if !is_access_intermediate(relationship.relation()) {
            continue;
        }
        let Some(first) = access_edge(relationship, entities) else {
            continue;
        };
        for second_relationship in &relationships {
            if second_relationship.from() != relationship.to()
                || !is_terminal_access(second_relationship.relation())
            {
                continue;
            }
            let Some(second) = access_edge(second_relationship, entities) else {
                continue;
            };
            access_observed = true;
            insert_bounded(
                facts,
                ContextFactV1::Access {
                    person: person.clone(),
                    target: second.to.clone(),
                    path: vec![first.clone(), second],
                },
                max_facts,
                truncated,
            );
        }
    }
    access_observed
}

fn access_edge(
    relationship: &cerebro_organizational_model::RelationshipAssertion,
    entities: &BTreeMap<EntityId, &Entity>,
) -> Option<ContextAccessEdgeV1> {
    Some(ContextAccessEdgeV1 {
        assertion_id: relationship.id().clone(),
        from: subject_ref(entities.get(relationship.from())?),
        relation: relationship.relation(),
        to: subject_ref(entities.get(relationship.to())?),
        source_runtime_id: relationship.provenance().source_runtime_id().clone(),
    })
}

fn is_access_intermediate(relation: RelationKind) -> bool {
    matches!(relation, RelationKind::MemberOf | RelationKind::CanAssume)
}

fn is_terminal_access(relation: RelationKind) -> bool {
    matches!(
        relation,
        RelationKind::CanAccess | RelationKind::Grants | RelationKind::CanAssume
    )
}

fn subject_ref(entity: &Entity) -> ContextSubjectRefV1 {
    ContextSubjectRefV1 {
        entity_id: entity.id().clone(),
        entity_kind: entity.kind().clone(),
    }
}

fn insert_bounded(
    facts: &mut BTreeSet<ContextFactV1>,
    fact: ContextFactV1,
    limit: usize,
    truncated: &mut bool,
) {
    facts.insert(fact);
    if facts.len() > limit {
        facts.pop_last();
        *truncated = true;
    }
}

fn validate_selector_key(value: String) -> Result<String, SnapshotError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_SELECTOR_KEY_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(SnapshotError::Invalid("selector key"));
    }
    Ok(value)
}

fn canonical_digest(value: &impl Serialize) -> Result<String, SnapshotError> {
    let bytes = serde_jcs::to_vec(value).map_err(|_| SnapshotError::Canonicalization)?;
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(7 + digest.len() * 2);
    encoded.push_str("sha256:");
    for byte in digest {
        use fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use cerebro_organizational_graph::OrganizationalGraph;
    use cerebro_organizational_model::{
        AssertionProvenance, CanonicalIdentity, CollectionId, CompleteCollection, Entity,
        GraphAssertion, IdentityBindingAssertion, IdentityClaim, IdentityResolutionMethod,
        ObservationId, ObservationRef, ProviderIdentity, ProviderKind, RelationshipAssertion,
        SourceRuntimeId,
    };

    use super::*;

    struct Fixture {
        graph: OrganizationalGraph,
        tenant: TenantId,
        person_key: String,
    }

    struct RevisionChangingGraph {
        graph: OrganizationalGraph,
        revision_reads: Cell<usize>,
    }

    impl GraphRead for RevisionChangingGraph {
        fn graph_revision(&self, tenant_id: &TenantId) -> u64 {
            let revision = self.graph.graph_revision(tenant_id);
            let reads = self.revision_reads.get();
            self.revision_reads.set(reads + 1);
            revision + u64::from(reads > 0)
        }

        fn entity(&self, tenant_id: &TenantId, entity_id: &EntityId) -> Option<Entity> {
            self.graph.entity(tenant_id, entity_id)
        }

        fn entities(&self, tenant_id: &TenantId) -> Vec<Entity> {
            self.graph.entities(tenant_id)
        }

        fn assertions(&self, tenant_id: &TenantId) -> Vec<GraphAssertion> {
            self.graph.assertions(tenant_id)
        }
    }

    fn fixture(secret_property: Option<&str>, access_targets: usize) -> Fixture {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let runtime = SourceRuntimeId::parse("okta-prod").unwrap();
        let collection = CompleteCollection::new(
            tenant.clone(),
            runtime.clone(),
            CollectionId::parse("collection-1").unwrap(),
            "identity-and-access",
            10,
        )
        .unwrap();
        let receipt = collection.receipt().clone();
        let provenance = || {
            AssertionProvenance::direct(
                vec![
                    ObservationRef::new(
                        &receipt,
                        ObservationId::parse("observation-1").unwrap(),
                        "okta.user:user-1",
                    )
                    .unwrap(),
                ],
                "snapshot-test",
                "v1",
            )
            .unwrap()
        };
        let claim = IdentityClaim::employee_id("employee-1").unwrap();
        let canonical = CanonicalIdentity::for_claim(tenant.clone(), &claim, "User One").unwrap();
        let person_key = canonical.entity().agent_key();
        let provider = ProviderIdentity::new(
            tenant.clone(),
            runtime,
            ProviderKind::parse("okta.user").unwrap(),
            "user-1",
            "User One",
        )
        .unwrap();
        let mut group = Entity::canonical(
            tenant.clone(),
            EntityId::parse("group-1").unwrap(),
            EntityKind::Group,
            "Engineering",
        )
        .unwrap();
        if let Some(secret) = secret_property {
            group = group
                .with_property("api_token", secret)
                .unwrap()
                .with_property(
                    "resource_urn",
                    format!("urn:cerebro:tenant-a:group:{secret}"),
                )
                .unwrap();
        }
        let binding = IdentityBindingAssertion::new(
            &provider,
            &canonical,
            IdentityResolutionMethod::AuthoritativeEmployeeId,
            Some(claim),
            IdentityBindingState::Confirmed,
            provenance(),
            10,
        )
        .unwrap();
        let membership = RelationshipAssertion::new(
            canonical.entity(),
            RelationKind::MemberOf,
            &group,
            provenance(),
            10,
        )
        .unwrap();
        let mut builder = collection.begin_delta();
        builder.add_entity(canonical.into_entity()).unwrap();
        builder.add_entity(provider.into_entity()).unwrap();
        builder.add_entity(group.clone()).unwrap();
        builder
            .add_assertion(GraphAssertion::IdentityBinding(binding))
            .unwrap();
        builder
            .add_assertion(GraphAssertion::Relationship(membership))
            .unwrap();
        for index in 0..access_targets {
            let resource = Entity::canonical(
                tenant.clone(),
                EntityId::parse(format!("repository-{index}")).unwrap(),
                EntityKind::Repository,
                format!("Repository {index}"),
            )
            .unwrap();
            let access = RelationshipAssertion::new(
                &group,
                RelationKind::CanAccess,
                &resource,
                provenance(),
                10,
            )
            .unwrap();
            builder.add_entity(resource).unwrap();
            builder
                .add_assertion(GraphAssertion::Relationship(access))
                .unwrap();
        }
        let mut graph = OrganizationalGraph::new();
        graph.apply(builder.build()).unwrap();
        Fixture {
            graph,
            tenant,
            person_key,
        }
    }

    #[test]
    fn stable_snapshot_resolves_person_and_access_at_one_revision() {
        let fixture = fixture(None, 1);
        let request = ContextSnapshotRequestV1::new(
            fixture.tenant.clone(),
            vec![
                ContextSelectorV1::access(&fixture.person_key).unwrap(),
                ContextSelectorV1::canonical_person(&fixture.person_key).unwrap(),
            ],
            20,
        )
        .unwrap();
        let left = ContextSnapshotV1::capture(&fixture.graph, request.clone()).unwrap();
        let right = ContextSnapshotV1::capture(&fixture.graph, request).unwrap();
        assert_eq!(left.snapshot_id(), right.snapshot_id());
        assert_eq!(left.snapshot_digest(), right.snapshot_digest());
        assert_eq!(left.graph_revision(), 1);
        assert_eq!(
            left.coverage().completeness(),
            ContextCoverageCompletenessV1::Complete
        );
        assert!(left.facts().iter().any(|fact| matches!(
            fact,
            ContextFactV1::Access { path, .. } if path.len() == 2
        )));
        left.verify().unwrap();
    }

    #[test]
    fn capture_rejects_a_revision_change_instead_of_mixing_graph_states() {
        let fixture = fixture(None, 1);
        let request = ContextSnapshotRequestV1::new(
            fixture.tenant,
            vec![ContextSelectorV1::access(fixture.person_key).unwrap()],
            20,
        )
        .unwrap();
        let graph = RevisionChangingGraph {
            graph: fixture.graph,
            revision_reads: Cell::new(0),
        };

        assert_eq!(
            ContextSnapshotV1::capture(&graph, request),
            Err(SnapshotError::RevisionChanged {
                before: 1,
                after: 2,
            })
        );
    }

    #[test]
    fn request_rejects_selector_sets_above_the_declared_bound() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let selectors = (0..=MAX_SELECTORS)
            .map(|index| ContextSelectorV1::canonical_person(format!("person-{index}")))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(
            ContextSnapshotRequestV1::new(tenant, selectors, 20),
            Err(SnapshotError::Invalid("selector count"))
        );
    }

    #[test]
    fn snapshot_is_tenant_scoped_even_when_another_tenant_reuses_a_key() {
        let mut fixture = fixture(None, 0);
        let other_tenant = TenantId::parse("tenant-b").unwrap();
        let other_collection = CompleteCollection::new(
            other_tenant.clone(),
            SourceRuntimeId::parse("other-runtime").unwrap(),
            CollectionId::parse("other-collection").unwrap(),
            "people",
            20,
        )
        .unwrap();
        let other = Entity::canonical(
            other_tenant,
            EntityId::parse("other-person").unwrap(),
            EntityKind::Person,
            "Other Person",
        )
        .unwrap()
        .with_property("entity_urn", fixture.person_key.clone())
        .unwrap();
        let mut builder = other_collection.begin_delta();
        builder.add_entity(other).unwrap();
        fixture.graph.apply(builder.build()).unwrap();

        let request = ContextSnapshotRequestV1::new(
            fixture.tenant,
            vec![ContextSelectorV1::canonical_person(fixture.person_key).unwrap()],
            10,
        )
        .unwrap();
        let snapshot = ContextSnapshotV1::capture(&fixture.graph, request).unwrap();
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(!json.contains("other-person"));
        assert!(!json.contains("tenant-b"));
    }

    #[test]
    fn ambiguity_is_explicit_and_never_selects_a_candidate() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let collection = CompleteCollection::new(
            tenant.clone(),
            SourceRuntimeId::parse("people-runtime").unwrap(),
            CollectionId::parse("ambiguous-collection").unwrap(),
            "people",
            10,
        )
        .unwrap();
        let shared_key = "urn:cerebro:tenant-a:person:shared";
        let mut builder = collection.begin_delta();
        for id in ["person-a", "person-b"] {
            builder
                .add_entity(
                    Entity::canonical(
                        tenant.clone(),
                        EntityId::parse(id).unwrap(),
                        EntityKind::Person,
                        id,
                    )
                    .unwrap()
                    .with_property("entity_urn", shared_key)
                    .unwrap(),
                )
                .unwrap();
        }
        let mut graph = OrganizationalGraph::new();
        graph.apply(builder.build()).unwrap();
        let request = ContextSnapshotRequestV1::new(
            tenant,
            vec![ContextSelectorV1::canonical_person(shared_key).unwrap()],
            10,
        )
        .unwrap();
        let snapshot = ContextSnapshotV1::capture(&graph, request).unwrap();
        assert_eq!(
            snapshot.subject_resolutions()[0].state(),
            ContextSubjectResolutionStateV1::Ambiguous
        );
        assert!(
            snapshot.subject_resolutions()[0]
                .canonical_person()
                .is_none()
        );
        assert_eq!(snapshot.contradictions().len(), 1);
        assert_eq!(snapshot.coverage().ambiguous_selectors(), 1);
        assert_eq!(
            snapshot.coverage().completeness(),
            ContextCoverageCompletenessV1::Partial
        );
    }

    #[test]
    fn fact_bound_marks_coverage_partial_and_output_stays_bounded() {
        let fixture = fixture(None, 5);
        let request = ContextSnapshotRequestV1::new(
            fixture.tenant,
            vec![ContextSelectorV1::access(fixture.person_key).unwrap()],
            2,
        )
        .unwrap();
        let snapshot = ContextSnapshotV1::capture(&fixture.graph, request).unwrap();
        assert_eq!(snapshot.facts().len(), 2);
        assert!(snapshot.coverage().facts_truncated());
        assert_eq!(
            snapshot.coverage().completeness(),
            ContextCoverageCompletenessV1::Partial
        );
        assert!(
            snapshot
                .unknowns()
                .iter()
                .any(|unknown| unknown.reason == ContextUnknownReasonV1::FactLimitReached)
        );
    }

    #[test]
    fn graph_properties_and_secret_values_never_enter_snapshot_bytes() {
        let fixture = fixture(Some("super-secret-token-value"), 1);
        let request = ContextSnapshotRequestV1::new(
            fixture.tenant,
            vec![ContextSelectorV1::access(fixture.person_key).unwrap()],
            20,
        )
        .unwrap();
        let snapshot = ContextSnapshotV1::capture(&fixture.graph, request).unwrap();
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(!json.contains("super-secret-token-value"));
        assert!(!json.contains("api_token"));
        assert!(!json.contains("resource_urn"));
    }

    #[test]
    fn missing_person_and_missing_access_are_explicit_unknowns() {
        let fixture = fixture(None, 0);
        let request = ContextSnapshotRequestV1::new(
            fixture.tenant,
            vec![
                ContextSelectorV1::access(fixture.person_key).unwrap(),
                ContextSelectorV1::canonical_person("missing-person").unwrap(),
            ],
            20,
        )
        .unwrap();
        let snapshot = ContextSnapshotV1::capture(&fixture.graph, request).unwrap();
        assert!(
            snapshot
                .unknowns()
                .iter()
                .any(|unknown| unknown.reason == ContextUnknownReasonV1::AccessNotObserved)
        );
        assert!(
            snapshot.unknowns().iter().any(|unknown| {
                unknown.reason == ContextUnknownReasonV1::CanonicalPersonNotFound
            })
        );
        assert_eq!(snapshot.coverage().unknown_selectors(), 1);
        assert_eq!(
            snapshot.coverage().completeness(),
            ContextCoverageCompletenessV1::Partial
        );
    }
}
