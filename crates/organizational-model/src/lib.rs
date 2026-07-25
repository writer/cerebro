#![forbid(unsafe_code)]

//! The sealed domain model for Cerebro's organizational graph.
//!
//! Validated values deliberately do not implement `Deserialize`. External data
//! must cross an admission boundary and use the constructors in this crate.

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
};

use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_ID_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelError {
    Empty(&'static str),
    Invalid(&'static str),
    TooLong(&'static str),
    TenantMismatch,
    CollectionMismatch,
    InvalidRelationship,
    InvalidIdentityBinding,
    EvidenceRequired,
    DuplicateEntity,
    DuplicateAssertion,
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(field) => write!(formatter, "{field} is required"),
            Self::Invalid(field) => write!(formatter, "{field} is invalid"),
            Self::TooLong(field) => write!(formatter, "{field} exceeds its size limit"),
            Self::TenantMismatch => formatter.write_str("graph values belong to different tenants"),
            Self::CollectionMismatch => {
                formatter.write_str("evidence belongs to a different collection")
            }
            Self::InvalidRelationship => {
                formatter.write_str("relationship does not accept these entity kinds")
            }
            Self::InvalidIdentityBinding => formatter.write_str(
                "identity binding must connect one provider identity to one canonical identity",
            ),
            Self::EvidenceRequired => formatter.write_str("assertion evidence is required"),
            Self::DuplicateEntity => {
                formatter.write_str("graph delta contains a conflicting entity")
            }
            Self::DuplicateAssertion => {
                formatter.write_str("graph delta contains a conflicting assertion")
            }
        }
    }
}

impl Error for ModelError {}

macro_rules! id_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                Ok(Self(validate_identifier(value.into(), $field)?))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

id_type!(TenantId, "tenant id");
id_type!(SourceRuntimeId, "source runtime id");
id_type!(CollectionId, "collection id");
id_type!(ObservationId, "observation id");
id_type!(EntityId, "entity id");
id_type!(AssertionId, "assertion id");
id_type!(CanonicalIdentityId, "canonical identity id");

fn validate_identifier(value: String, field: &'static str) -> Result<String, ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty(field));
    }
    if value.trim() != value
        || value.len() > MAX_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
    {
        return Err(ModelError::Invalid(field));
    }
    Ok(value)
}

fn validate_text(value: String, field: &'static str) -> Result<String, ModelError> {
    if value.trim().is_empty() {
        return Err(ModelError::Empty(field));
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::Invalid(field));
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(ModelError::TooLong(field));
    }
    Ok(value)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProviderKind(String);

impl ProviderKind {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = validate_identifier(value.into(), "provider entity kind")?;
        if !value.contains('.') {
            return Err(ModelError::Invalid("provider entity kind"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Person,
    Identity,
    Team,
    Organization,
    Repository,
    Service,
    Application,
    Environment,
    Account,
    Resource,
    Group,
    Role,
    Policy,
    Control,
    Finding,
    Framework,
    Program,
    Objective,
    Rule,
    Evidence,
    AssessmentRun,
    AssessmentResult,
    AssessmentSnapshot,
    Remediation,
    Verification,
    WorkItem,
    Provider(ProviderKind),
}

impl EntityKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::Identity => "identity",
            Self::Team => "team",
            Self::Organization => "organization",
            Self::Repository => "repository",
            Self::Service => "service",
            Self::Application => "application",
            Self::Environment => "environment",
            Self::Account => "account",
            Self::Resource => "resource",
            Self::Group => "group",
            Self::Role => "role",
            Self::Policy => "policy",
            Self::Control => "control",
            Self::Finding => "finding",
            Self::Framework => "framework",
            Self::Program => "program",
            Self::Objective => "objective",
            Self::Rule => "rule",
            Self::Evidence => "evidence",
            Self::AssessmentRun => "assessment_run",
            Self::AssessmentResult => "assessment_result",
            Self::AssessmentSnapshot => "assessment_snapshot",
            Self::Remediation => "remediation",
            Self::Verification => "verification",
            Self::WorkItem => "work_item",
            Self::Provider(_) => "provider",
        }
    }

    pub fn is_wire_name(value: &str) -> bool {
        matches!(
            value,
            "person"
                | "identity"
                | "team"
                | "organization"
                | "repository"
                | "service"
                | "application"
                | "environment"
                | "account"
                | "resource"
                | "group"
                | "role"
                | "policy"
                | "control"
                | "finding"
                | "framework"
                | "program"
                | "objective"
                | "rule"
                | "evidence"
                | "assessment_run"
                | "assessment_result"
                | "assessment_snapshot"
                | "remediation"
                | "verification"
                | "work_item"
                | "provider"
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "authority", rename_all = "snake_case")]
pub enum EntityAuthority {
    Canonical,
    Provider {
        source_runtime_id: SourceRuntimeId,
        provider_kind: ProviderKind,
        provider_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Entity {
    id: EntityId,
    tenant_id: TenantId,
    kind: EntityKind,
    authority: EntityAuthority,
    label: String,
    properties: BTreeMap<String, String>,
}

impl Entity {
    pub fn canonical(
        tenant_id: TenantId,
        id: EntityId,
        kind: EntityKind,
        label: impl Into<String>,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            id,
            tenant_id,
            kind,
            authority: EntityAuthority::Canonical,
            label: validate_text(label.into(), "entity label")?,
            properties: BTreeMap::new(),
        })
    }

    pub fn provider(
        tenant_id: TenantId,
        source_runtime_id: SourceRuntimeId,
        provider_kind: ProviderKind,
        provider_id: impl Into<String>,
        kind: EntityKind,
        label: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let provider_id = validate_text(provider_id.into(), "provider id")?;
        let id = EntityId::parse(deterministic_id(
            "entity",
            &[
                tenant_id.as_str(),
                source_runtime_id.as_str(),
                provider_kind.as_str(),
                &provider_id,
            ],
        ))?;
        Ok(Self {
            id,
            tenant_id,
            kind,
            authority: EntityAuthority::Provider {
                source_runtime_id,
                provider_kind,
                provider_id,
            },
            label: validate_text(label.into(), "entity label")?,
            properties: BTreeMap::new(),
        })
    }

    pub fn with_property(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let key = validate_identifier(key.into(), "property key")?;
        let value = validate_text(value.into(), "property value")?;
        self.properties.insert(key, value);
        Ok(self)
    }

    pub fn id(&self) -> &EntityId {
        &self.id
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn kind(&self) -> &EntityKind {
        &self.kind
    }

    pub fn authority(&self) -> &EntityAuthority {
        &self.authority
    }

    /// Stable identity fields cannot change when a source refreshes mutable
    /// presentation data such as labels and properties.
    pub fn has_same_identity(&self, other: &Self) -> bool {
        self.id == other.id
            && self.tenant_id == other.tenant_id
            && self.kind == other.kind
            && self.authority == other.authority
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn properties(&self) -> &BTreeMap<String, String> {
        &self.properties
    }

    /// Returns the tenant-scoped key exposed at agent and product boundaries.
    ///
    /// Provider projections may carry an existing Cerebro URN. Values for a
    /// different tenant are never accepted as aliases. Every other entity gets
    /// a deterministic key derived from its sealed tenant and entity ID.
    pub fn agent_key(&self) -> String {
        for property in ["resource_urn", "entity_urn", "urn"] {
            if let Some(value) = self.properties.get(property)
                && value
                    .strip_prefix("urn:cerebro:")
                    .and_then(|suffix| suffix.split_once(':'))
                    .is_some_and(|(tenant_id, remainder)| {
                        tenant_id == self.tenant_id.as_str() && !remainder.is_empty()
                    })
            {
                return value.clone();
            }
        }
        format!(
            "urn:cerebro:{}:organizational_entity:{}",
            self.tenant_id.as_str(),
            self.id.as_str()
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanonicalIdentity(Entity);

impl CanonicalIdentity {
    pub fn new(
        tenant_id: TenantId,
        id: CanonicalIdentityId,
        label: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let entity_id = EntityId::parse(format!("person:canonical:{id}"))?;
        Ok(Self(Entity::canonical(
            tenant_id,
            entity_id,
            EntityKind::Person,
            label,
        )?))
    }

    pub fn for_claim(
        tenant_id: TenantId,
        claim: &IdentityClaim,
        label: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let id = CanonicalIdentityId::parse(deterministic_id(
            "claim",
            &[tenant_id.as_str(), claim.kind().as_str(), claim.value()],
        ))?;
        Self::new(tenant_id, id, label)
    }

    pub fn entity(&self) -> &Entity {
        &self.0
    }

    pub fn into_entity(self) -> Entity {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderIdentity(Entity);

impl ProviderIdentity {
    pub fn new(
        tenant_id: TenantId,
        source_runtime_id: SourceRuntimeId,
        provider_kind: ProviderKind,
        provider_id: impl Into<String>,
        label: impl Into<String>,
    ) -> Result<Self, ModelError> {
        Ok(Self(Entity::provider(
            tenant_id,
            source_runtime_id,
            provider_kind,
            provider_id,
            EntityKind::Identity,
            label,
        )?))
    }

    pub fn entity(&self) -> &Entity {
        &self.0
    }

    pub fn into_entity(self) -> Entity {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionCompleteness {
    Partial,
    Incremental,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CollectionReceipt {
    tenant_id: TenantId,
    source_runtime_id: SourceRuntimeId,
    collection_id: CollectionId,
    scope: String,
    completeness: CollectionCompleteness,
    observed_at_unix_ms: i64,
}

impl CollectionReceipt {
    pub fn partial(
        tenant_id: TenantId,
        source_runtime_id: SourceRuntimeId,
        collection_id: CollectionId,
        scope: impl Into<String>,
        observed_at_unix_ms: i64,
    ) -> Result<Self, ModelError> {
        Self::new(
            tenant_id,
            source_runtime_id,
            collection_id,
            scope,
            CollectionCompleteness::Partial,
            observed_at_unix_ms,
        )
    }

    pub fn incremental(
        tenant_id: TenantId,
        source_runtime_id: SourceRuntimeId,
        collection_id: CollectionId,
        scope: impl Into<String>,
        observed_at_unix_ms: i64,
    ) -> Result<Self, ModelError> {
        Self::new(
            tenant_id,
            source_runtime_id,
            collection_id,
            scope,
            CollectionCompleteness::Incremental,
            observed_at_unix_ms,
        )
    }

    fn new(
        tenant_id: TenantId,
        source_runtime_id: SourceRuntimeId,
        collection_id: CollectionId,
        scope: impl Into<String>,
        completeness: CollectionCompleteness,
        observed_at_unix_ms: i64,
    ) -> Result<Self, ModelError> {
        if observed_at_unix_ms <= 0 {
            return Err(ModelError::Invalid("collection observed time"));
        }
        Ok(Self {
            tenant_id,
            source_runtime_id,
            collection_id,
            scope: validate_text(scope.into(), "collection scope")?,
            completeness,
            observed_at_unix_ms,
        })
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn source_runtime_id(&self) -> &SourceRuntimeId {
        &self.source_runtime_id
    }

    pub fn collection_id(&self) -> &CollectionId {
        &self.collection_id
    }

    pub fn completeness(&self) -> &CollectionCompleteness {
        &self.completeness
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn observed_at_unix_ms(&self) -> i64 {
        self.observed_at_unix_ms
    }

    pub fn begin_delta(self) -> GraphDeltaBuilder<NonAuthoritative> {
        GraphDeltaBuilder::new(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompleteCollection(CollectionReceipt);

impl CompleteCollection {
    pub fn new(
        tenant_id: TenantId,
        source_runtime_id: SourceRuntimeId,
        collection_id: CollectionId,
        scope: impl Into<String>,
        observed_at_unix_ms: i64,
    ) -> Result<Self, ModelError> {
        Ok(Self(CollectionReceipt::new(
            tenant_id,
            source_runtime_id,
            collection_id,
            scope,
            CollectionCompleteness::Complete,
            observed_at_unix_ms,
        )?))
    }

    pub fn receipt(&self) -> &CollectionReceipt {
        &self.0
    }

    pub fn begin_delta(self) -> GraphDeltaBuilder<Authoritative> {
        GraphDeltaBuilder::new(self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ObservationRef {
    observation_id: ObservationId,
    tenant_id: TenantId,
    source_runtime_id: SourceRuntimeId,
    collection_id: CollectionId,
    source_record: String,
}

impl ObservationRef {
    pub fn new(
        receipt: &CollectionReceipt,
        observation_id: ObservationId,
        source_record: impl Into<String>,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            observation_id,
            tenant_id: receipt.tenant_id.clone(),
            source_runtime_id: receipt.source_runtime_id.clone(),
            collection_id: receipt.collection_id.clone(),
            source_record: validate_text(source_record.into(), "source record")?,
        })
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn observation_id(&self) -> &ObservationId {
        &self.observation_id
    }

    pub fn source_runtime_id(&self) -> &SourceRuntimeId {
        &self.source_runtime_id
    }

    pub fn collection_id(&self) -> &CollectionId {
        &self.collection_id
    }

    pub fn source_record(&self) -> &str {
        &self.source_record
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AssertionProvenance {
    observations: Vec<ObservationRef>,
    producer: String,
    producer_version: String,
}

impl AssertionProvenance {
    pub fn direct(
        observations: Vec<ObservationRef>,
        producer: impl Into<String>,
        producer_version: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let first = observations.first().ok_or(ModelError::EvidenceRequired)?;
        if observations.iter().any(|item| {
            item.tenant_id != first.tenant_id
                || item.source_runtime_id != first.source_runtime_id
                || item.collection_id != first.collection_id
        }) {
            return Err(ModelError::CollectionMismatch);
        }
        Ok(Self {
            observations,
            producer: validate_identifier(producer.into(), "assertion producer")?,
            producer_version: validate_identifier(
                producer_version.into(),
                "assertion producer version",
            )?,
        })
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.observations[0].tenant_id
    }

    pub fn source_runtime_id(&self) -> &SourceRuntimeId {
        &self.observations[0].source_runtime_id
    }

    pub fn observations(&self) -> &[ObservationRef] {
        &self.observations
    }

    pub fn producer(&self) -> &str {
        &self.producer
    }

    pub fn producer_version(&self) -> &str {
        &self.producer_version
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    MemberOf,
    Owns,
    Maintains,
    DependsOn,
    Builds,
    Deploys,
    RunsIn,
    Contains,
    CanAssume,
    CanAccess,
    Grants,
    ProvisionedAs,
    Governs,
    Affects,
    Supports,
    EvidenceFor,
    MappedToControl,
    TrackedBy,
    Implements,
    Tests,
    Includes,
    Scopes,
    Uses,
    Evaluates,
    Assesses,
    Cites,
    DetectedBy,
    Addresses,
    Verifies,
    Commits,
    DerivedFrom,
}

impl RelationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MemberOf => "member_of",
            Self::Owns => "owns",
            Self::Maintains => "maintains",
            Self::DependsOn => "depends_on",
            Self::Builds => "builds",
            Self::Deploys => "deploys",
            Self::RunsIn => "runs_in",
            Self::Contains => "contains",
            Self::CanAssume => "can_assume",
            Self::CanAccess => "can_access",
            Self::Grants => "grants",
            Self::ProvisionedAs => "provisioned_as",
            Self::Governs => "governs",
            Self::Affects => "affects",
            Self::Supports => "supports",
            Self::EvidenceFor => "evidence_for",
            Self::MappedToControl => "mapped_to_control",
            Self::TrackedBy => "tracked_by",
            Self::Implements => "implements",
            Self::Tests => "tests",
            Self::Includes => "includes",
            Self::Scopes => "scopes",
            Self::Uses => "uses",
            Self::Evaluates => "evaluates",
            Self::Assesses => "assesses",
            Self::Cites => "cites",
            Self::DetectedBy => "detected_by",
            Self::Addresses => "addresses",
            Self::Verifies => "verifies",
            Self::Commits => "commits",
            Self::DerivedFrom => "derived_from",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        Some(match value {
            "member_of" => Self::MemberOf,
            "owns" => Self::Owns,
            "maintains" => Self::Maintains,
            "depends_on" => Self::DependsOn,
            "builds" => Self::Builds,
            "deploys" => Self::Deploys,
            "runs_in" => Self::RunsIn,
            "contains" => Self::Contains,
            "can_assume" => Self::CanAssume,
            "can_access" => Self::CanAccess,
            "grants" => Self::Grants,
            "provisioned_as" => Self::ProvisionedAs,
            "governs" => Self::Governs,
            "affects" => Self::Affects,
            "supports" => Self::Supports,
            "evidence_for" => Self::EvidenceFor,
            "mapped_to_control" => Self::MappedToControl,
            "tracked_by" => Self::TrackedBy,
            "implements" => Self::Implements,
            "tests" => Self::Tests,
            "includes" => Self::Includes,
            "scopes" => Self::Scopes,
            "uses" => Self::Uses,
            "evaluates" => Self::Evaluates,
            "assesses" => Self::Assesses,
            "cites" => Self::Cites,
            "detected_by" => Self::DetectedBy,
            "addresses" => Self::Addresses,
            "verifies" => Self::Verifies,
            "commits" => Self::Commits,
            "derived_from" => Self::DerivedFrom,
            _ => return None,
        })
    }

    pub fn accepts(self, from: &EntityKind, to: &EntityKind) -> bool {
        use EntityKind::*;
        match self {
            Self::MemberOf => matches!(from, Identity | Person) && matches!(to, Group | Team),
            Self::Owns | Self::Maintains => {
                matches!(from, Person | Team | Organization)
                    && matches!(
                        to,
                        Repository | Service | Application | Account | Resource | Control
                    )
            }
            Self::DependsOn => !matches!(from, Finding) && !matches!(to, Finding),
            Self::Builds => matches!(from, Repository) && matches!(to, Service | Application),
            Self::Deploys => matches!(from, Repository | Service) && matches!(to, Environment),
            Self::RunsIn => {
                matches!(from, Service | Application | Resource)
                    && matches!(to, Environment | Account)
            }
            Self::Contains => {
                matches!(from, Organization | Account | Environment | Group)
                    && !matches!(to, Person)
            }
            Self::CanAssume => matches!(from, Identity | Role) && matches!(to, Role),
            Self::CanAccess => {
                matches!(from, Identity | Group | Role | Application | Service)
                    && matches!(
                        to,
                        Repository | Service | Application | Account | Resource | Environment
                    )
            }
            Self::Grants => {
                matches!(from, Group | Team | Role | Policy)
                    && matches!(
                        to,
                        Role | Repository
                            | Service
                            | Application
                            | Account
                            | Resource
                            | Environment
                    )
            }
            Self::ProvisionedAs => matches!(from, Group) && matches!(to, Team | Role | Group),
            Self::Governs => matches!(from, Policy | Control) && !matches!(to, Person | Identity),
            Self::Affects => matches!(from, Finding) && !matches!(to, Finding),
            Self::Supports => {
                !matches!(from, Finding) && matches!(to, Service | Application | Control)
            }
            Self::EvidenceFor => {
                !matches!(from, Person | Identity) && matches!(to, Finding | Control)
            }
            Self::MappedToControl => matches!(from, Finding | Policy) && matches!(to, Control),
            Self::TrackedBy => !matches!(from, Person | Identity) && matches!(to, Provider(_)),
            Self::Implements => matches!(from, Policy) && matches!(to, Control),
            Self::Tests => matches!(from, Rule) && matches!(to, Objective),
            Self::Includes => {
                matches!(from, Framework | Program) && matches!(to, Control | Objective | Policy)
            }
            Self::Scopes => {
                matches!(from, Program)
                    && !matches!(
                        to,
                        Framework
                            | Program
                            | AssessmentRun
                            | AssessmentResult
                            | AssessmentSnapshot
                            | Remediation
                            | Verification
                            | WorkItem
                    )
            }
            Self::Uses => {
                matches!(from, AssessmentRun)
                    && matches!(to, Program | Policy | Rule | AssessmentSnapshot)
            }
            Self::Evaluates => {
                matches!(from, AssessmentResult) && matches!(to, Objective | Control)
            }
            Self::Assesses => {
                matches!(from, AssessmentResult)
                    && !matches!(
                        to,
                        Framework
                            | Program
                            | Objective
                            | Rule
                            | Evidence
                            | AssessmentRun
                            | AssessmentResult
                            | AssessmentSnapshot
                            | Remediation
                            | Verification
                            | WorkItem
                    )
            }
            Self::Cites => {
                matches!(
                    from,
                    Finding | AssessmentResult | AssessmentSnapshot | Verification
                ) && matches!(to, Evidence)
            }
            Self::DetectedBy => matches!(from, Finding) && matches!(to, Rule),
            Self::Addresses => matches!(from, Remediation | WorkItem) && matches!(to, Finding),
            Self::Verifies => matches!(from, Verification) && matches!(to, Remediation | Finding),
            Self::Commits => matches!(from, AssessmentSnapshot) && matches!(to, AssessmentResult),
            Self::DerivedFrom => {
                matches!(from, Finding | AssessmentResult | Verification)
                    && !matches!(to, Person | Identity)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RelationshipAssertion {
    id: AssertionId,
    tenant_id: TenantId,
    from: EntityId,
    from_kind: EntityKind,
    relation: RelationKind,
    to: EntityId,
    to_kind: EntityKind,
    provenance: AssertionProvenance,
    observed_at_unix_ms: i64,
}

impl RelationshipAssertion {
    pub fn new(
        from: &Entity,
        relation: RelationKind,
        to: &Entity,
        provenance: AssertionProvenance,
        observed_at_unix_ms: i64,
    ) -> Result<Self, ModelError> {
        if from.tenant_id != to.tenant_id || from.tenant_id != *provenance.tenant_id() {
            return Err(ModelError::TenantMismatch);
        }
        if !relation.accepts(&from.kind, &to.kind) || observed_at_unix_ms <= 0 {
            return Err(ModelError::InvalidRelationship);
        }
        let id = AssertionId::parse(deterministic_id(
            "assertion",
            &[
                from.tenant_id.as_str(),
                from.id.as_str(),
                relation.as_str(),
                to.id.as_str(),
                provenance.source_runtime_id().as_str(),
            ],
        ))?;
        Ok(Self {
            id,
            tenant_id: from.tenant_id.clone(),
            from: from.id.clone(),
            from_kind: from.kind.clone(),
            relation,
            to: to.id.clone(),
            to_kind: to.kind.clone(),
            provenance,
            observed_at_unix_ms,
        })
    }

    pub fn id(&self) -> &AssertionId {
        &self.id
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn from(&self) -> &EntityId {
        &self.from
    }

    pub fn to(&self) -> &EntityId {
        &self.to
    }

    pub fn relation(&self) -> RelationKind {
        self.relation
    }

    pub fn provenance(&self) -> &AssertionProvenance {
        &self.provenance
    }

    pub fn observed_at_unix_ms(&self) -> i64 {
        self.observed_at_unix_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityResolutionMethod {
    AuthoritativeEmployeeId,
    VerifiedEmail,
    ExistingClaimMatch,
    HumanDecision,
    AgentProposal,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityClaimKind {
    EmployeeId,
    VerifiedEmail,
}

impl IdentityClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmployeeId => "employee_id",
            Self::VerifiedEmail => "verified_email",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdentityClaim {
    kind: IdentityClaimKind,
    value: String,
}

impl IdentityClaim {
    pub fn employee_id(value: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self {
            kind: IdentityClaimKind::EmployeeId,
            value: validate_text(value.into(), "employee id")?,
        })
    }

    pub fn verified_email(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = validate_text(value.into(), "verified email")?.to_lowercase();
        let (local, domain) = value
            .split_once('@')
            .ok_or(ModelError::Invalid("verified email"))?;
        if local.is_empty() || domain.is_empty() || !domain.contains('.') {
            return Err(ModelError::Invalid("verified email"));
        }
        Ok(Self {
            kind: IdentityClaimKind::VerifiedEmail,
            value,
        })
    }

    pub fn kind(&self) -> IdentityClaimKind {
        self.kind
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityBindingState {
    Proposed,
    Confirmed,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdentityBindingAssertion {
    id: AssertionId,
    tenant_id: TenantId,
    provider_identity: EntityId,
    canonical_identity: EntityId,
    method: IdentityResolutionMethod,
    provider_kind: ProviderKind,
    claim: Option<IdentityClaim>,
    state: IdentityBindingState,
    provenance: AssertionProvenance,
    observed_at_unix_ms: i64,
}

impl IdentityBindingAssertion {
    pub fn new(
        provider: &ProviderIdentity,
        canonical: &CanonicalIdentity,
        method: IdentityResolutionMethod,
        claim: Option<IdentityClaim>,
        state: IdentityBindingState,
        provenance: AssertionProvenance,
        observed_at_unix_ms: i64,
    ) -> Result<Self, ModelError> {
        if provider.entity().tenant_id != canonical.entity().tenant_id
            || provider.entity().tenant_id != *provenance.tenant_id()
            || observed_at_unix_ms <= 0
        {
            return Err(ModelError::InvalidIdentityBinding);
        }
        if method == IdentityResolutionMethod::AgentProposal
            && state == IdentityBindingState::Confirmed
        {
            return Err(ModelError::InvalidIdentityBinding);
        }
        if state == IdentityBindingState::Confirmed {
            let valid_claim = matches!(
                (method, claim.as_ref().map(IdentityClaim::kind)),
                (
                    IdentityResolutionMethod::AuthoritativeEmployeeId,
                    Some(IdentityClaimKind::EmployeeId)
                ) | (
                    IdentityResolutionMethod::VerifiedEmail,
                    Some(IdentityClaimKind::VerifiedEmail)
                ) | (
                    IdentityResolutionMethod::ExistingClaimMatch,
                    Some(IdentityClaimKind::VerifiedEmail)
                ) | (IdentityResolutionMethod::HumanDecision, _)
            );
            if !valid_claim {
                return Err(ModelError::InvalidIdentityBinding);
            }
            let provider_kind = match provider.entity().authority() {
                EntityAuthority::Provider { provider_kind, .. } => provider_kind,
                EntityAuthority::Canonical => return Err(ModelError::InvalidIdentityBinding),
            };
            if matches!(
                method,
                IdentityResolutionMethod::AuthoritativeEmployeeId
                    | IdentityResolutionMethod::VerifiedEmail
            ) && !matches!(provider_kind.as_str(), "okta.user" | "okta.identity_user")
            {
                return Err(ModelError::InvalidIdentityBinding);
            }
            if method == IdentityResolutionMethod::AuthoritativeEmployeeId {
                let claim = claim.as_ref().ok_or(ModelError::InvalidIdentityBinding)?;
                let expected = CanonicalIdentity::for_claim(
                    provider.entity().tenant_id.clone(),
                    claim,
                    canonical.entity().label.clone(),
                )?;
                if expected.entity().id != canonical.entity().id {
                    return Err(ModelError::InvalidIdentityBinding);
                }
            }
        }
        let provider_kind = match provider.entity().authority() {
            EntityAuthority::Provider { provider_kind, .. } => provider_kind.clone(),
            EntityAuthority::Canonical => return Err(ModelError::InvalidIdentityBinding),
        };
        let claim_value = claim.as_ref().map(IdentityClaim::value).unwrap_or("");
        let id = AssertionId::parse(deterministic_id(
            "identity-binding",
            &[
                provider.entity().tenant_id.as_str(),
                provider.entity().id.as_str(),
                canonical.entity().id.as_str(),
                provenance.source_runtime_id().as_str(),
                claim_value,
            ],
        ))?;
        Ok(Self {
            id,
            tenant_id: provider.entity().tenant_id.clone(),
            provider_identity: provider.entity().id.clone(),
            canonical_identity: canonical.entity().id.clone(),
            method,
            provider_kind,
            claim,
            state,
            provenance,
            observed_at_unix_ms,
        })
    }

    pub fn id(&self) -> &AssertionId {
        &self.id
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn provider_identity(&self) -> &EntityId {
        &self.provider_identity
    }

    pub fn canonical_identity(&self) -> &EntityId {
        &self.canonical_identity
    }

    pub fn state(&self) -> IdentityBindingState {
        self.state
    }

    pub fn method(&self) -> IdentityResolutionMethod {
        self.method
    }

    pub fn provider_kind(&self) -> &ProviderKind {
        &self.provider_kind
    }

    pub fn claim(&self) -> Option<&IdentityClaim> {
        self.claim.as_ref()
    }

    pub fn provenance(&self) -> &AssertionProvenance {
        &self.provenance
    }

    pub fn observed_at_unix_ms(&self) -> i64 {
        self.observed_at_unix_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "assertion_type", rename_all = "snake_case")]
pub enum GraphAssertion {
    Relationship(RelationshipAssertion),
    IdentityBinding(IdentityBindingAssertion),
}

impl GraphAssertion {
    pub fn id(&self) -> &AssertionId {
        match self {
            Self::Relationship(value) => value.id(),
            Self::IdentityBinding(value) => value.id(),
        }
    }

    pub fn tenant_id(&self) -> &TenantId {
        match self {
            Self::Relationship(value) => value.tenant_id(),
            Self::IdentityBinding(value) => value.tenant_id(),
        }
    }

    pub fn provenance(&self) -> &AssertionProvenance {
        match self {
            Self::Relationship(value) => value.provenance(),
            Self::IdentityBinding(value) => value.provenance(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Retraction {
    assertion_id: AssertionId,
    reason: String,
}

impl Retraction {
    pub fn assertion_id(&self) -> &AssertionId {
        &self.assertion_id
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

pub struct NonAuthoritative;
pub struct Authoritative;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GraphDelta {
    collection: CollectionReceipt,
    entities: Vec<Entity>,
    assertions: Vec<GraphAssertion>,
    retractions: Vec<Retraction>,
    digest: String,
}

impl GraphDelta {
    pub fn collection(&self) -> &CollectionReceipt {
        &self.collection
    }

    pub fn entities(&self) -> &[Entity] {
        &self.entities
    }

    pub fn assertions(&self) -> &[GraphAssertion] {
        &self.assertions
    }

    pub fn retractions(&self) -> &[Retraction] {
        &self.retractions
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Transfers an already validated delta into the graph engine without
    /// cloning its entities or assertions.
    pub fn into_components(
        self,
    ) -> (
        CollectionReceipt,
        Vec<Entity>,
        Vec<GraphAssertion>,
        Vec<Retraction>,
        String,
    ) {
        (
            self.collection,
            self.entities,
            self.assertions,
            self.retractions,
            self.digest,
        )
    }
}

pub struct GraphDeltaBuilder<Mode> {
    collection: CollectionReceipt,
    entities: Vec<Entity>,
    entity_indexes: HashMap<EntityId, usize>,
    assertions: Vec<GraphAssertion>,
    assertion_indexes: HashMap<AssertionId, usize>,
    retractions: Vec<Retraction>,
    retraction_indexes: HashMap<AssertionId, usize>,
    _mode: std::marker::PhantomData<Mode>,
}

impl<Mode> GraphDeltaBuilder<Mode> {
    fn new(collection: CollectionReceipt) -> Self {
        Self {
            collection,
            entities: Vec::new(),
            entity_indexes: HashMap::new(),
            assertions: Vec::new(),
            assertion_indexes: HashMap::new(),
            retractions: Vec::new(),
            retraction_indexes: HashMap::new(),
            _mode: std::marker::PhantomData,
        }
    }

    pub fn add_entity(&mut self, entity: Entity) -> Result<(), ModelError> {
        if entity.tenant_id != self.collection.tenant_id {
            return Err(ModelError::TenantMismatch);
        }
        if let Some(index) = self.entity_indexes.get(&entity.id).copied() {
            if self.entities[index] != entity {
                return Err(ModelError::DuplicateEntity);
            }
            return Ok(());
        }
        self.entity_indexes
            .insert(entity.id.clone(), self.entities.len());
        self.entities.push(entity);
        Ok(())
    }

    pub fn add_assertion(&mut self, assertion: GraphAssertion) -> Result<(), ModelError> {
        if assertion.tenant_id() != &self.collection.tenant_id
            || assertion.provenance().source_runtime_id() != &self.collection.source_runtime_id
        {
            return Err(ModelError::TenantMismatch);
        }
        if let Some(index) = self.assertion_indexes.get(assertion.id()).copied() {
            if self.assertions[index] != assertion {
                return Err(ModelError::DuplicateAssertion);
            }
            return Ok(());
        }
        self.assertion_indexes
            .insert(assertion.id().clone(), self.assertions.len());
        self.assertions.push(assertion);
        Ok(())
    }

    pub fn build(mut self) -> GraphDelta {
        self.entities
            .sort_unstable_by(|left, right| left.id.cmp(&right.id));
        self.assertions
            .sort_unstable_by(|left, right| left.id().cmp(right.id()));
        self.retractions
            .sort_unstable_by(|left, right| left.assertion_id.cmp(&right.assertion_id));
        let digest = delta_digest(
            &self.collection,
            &self.entities,
            &self.assertions,
            &self.retractions,
        );
        GraphDelta {
            collection: self.collection,
            entities: self.entities,
            assertions: self.assertions,
            retractions: self.retractions,
            digest,
        }
    }
}

impl GraphDeltaBuilder<Authoritative> {
    pub fn retract_missing(
        &mut self,
        assertion_id: AssertionId,
        reason: impl Into<String>,
    ) -> Result<(), ModelError> {
        let retraction = Retraction {
            assertion_id,
            reason: validate_text(reason.into(), "retraction reason")?,
        };
        if let Some(index) = self
            .retraction_indexes
            .get(&retraction.assertion_id)
            .copied()
        {
            self.retractions[index] = retraction;
        } else {
            self.retraction_indexes
                .insert(retraction.assertion_id.clone(), self.retractions.len());
            self.retractions.push(retraction);
        }
        Ok(())
    }
}

fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    let mut id = String::with_capacity(prefix.len() + 33);
    id.push_str(prefix);
    id.push(':');
    append_hex(&mut id, &digest[..16]);
    id
}

fn delta_digest(
    collection: &CollectionReceipt,
    entities: &[Entity],
    assertions: &[GraphAssertion],
    retractions: &[Retraction],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(collection.tenant_id.as_str());
    hasher.update(collection.source_runtime_id.as_str());
    hasher.update(collection.collection_id.as_str());
    for entity in entities {
        hasher.update(entity.id.as_str());
    }
    for assertion in assertions {
        hasher.update(assertion.id().as_str());
    }
    for retraction in retractions {
        hasher.update(retraction.assertion_id.as_str());
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(7 + digest.len() * 2);
    encoded.push_str("sha256:");
    append_hex(&mut encoded, digest.as_slice());
    encoded
}

fn append_hex(encoded: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> CompleteCollection {
        CompleteCollection::new(
            TenantId::parse("tenant-a").unwrap(),
            SourceRuntimeId::parse("okta-prod").unwrap(),
            CollectionId::parse("collection-1").unwrap(),
            "okta.users",
            10,
        )
        .unwrap()
    }

    fn provenance(receipt: &CollectionReceipt) -> AssertionProvenance {
        AssertionProvenance::direct(
            vec![
                ObservationRef::new(
                    receipt,
                    ObservationId::parse("observation-1").unwrap(),
                    "okta.user:00u1",
                )
                .unwrap(),
            ],
            "okta-user-mapper",
            "v1",
        )
        .unwrap()
    }

    #[test]
    fn agent_proposals_cannot_confirm_unified_identity() {
        let receipt = receipt();
        let provider = ProviderIdentity::new(
            TenantId::parse("tenant-a").unwrap(),
            SourceRuntimeId::parse("okta-prod").unwrap(),
            ProviderKind::parse("okta.user").unwrap(),
            "00u1",
            "A Person",
        )
        .unwrap();
        let canonical = CanonicalIdentity::new(
            TenantId::parse("tenant-a").unwrap(),
            CanonicalIdentityId::parse("person-1").unwrap(),
            "A Person",
        )
        .unwrap();

        assert_eq!(
            IdentityBindingAssertion::new(
                &provider,
                &canonical,
                IdentityResolutionMethod::AgentProposal,
                None,
                IdentityBindingState::Confirmed,
                provenance(receipt.receipt()),
                10,
            ),
            Err(ModelError::InvalidIdentityBinding)
        );
    }

    #[test]
    fn verified_claims_derive_one_canonical_identity() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let first = IdentityClaim::verified_email("Person@Example.COM").unwrap();
        let second = IdentityClaim::verified_email("person@example.com").unwrap();
        let first_identity =
            CanonicalIdentity::for_claim(tenant.clone(), &first, "A Person").unwrap();
        let second_identity = CanonicalIdentity::for_claim(tenant, &second, "A Person").unwrap();
        assert_eq!(first.value(), "person@example.com");
        assert_eq!(first_identity.entity().id(), second_identity.entity().id());
    }

    #[test]
    fn every_entity_has_one_tenant_scoped_agent_key() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let entity = Entity::canonical(
            tenant,
            EntityId::parse("person:canonical:one").unwrap(),
            EntityKind::Person,
            "One",
        )
        .unwrap();
        assert_eq!(
            entity.agent_key(),
            "urn:cerebro:tenant-a:organizational_entity:person:canonical:one"
        );

        let declared = entity
            .clone()
            .with_property("resource_urn", "urn:cerebro:tenant-a:directory_user:one")
            .unwrap();
        assert_eq!(
            declared.agent_key(),
            "urn:cerebro:tenant-a:directory_user:one"
        );

        let cross_tenant = entity
            .with_property("resource_urn", "urn:cerebro:tenant-b:directory_user:one")
            .unwrap();
        assert_eq!(
            cross_tenant.agent_key(),
            "urn:cerebro:tenant-a:organizational_entity:person:canonical:one"
        );
    }

    #[test]
    fn relationship_endpoints_are_enforced() {
        let receipt = receipt();
        let repository = Entity::canonical(
            TenantId::parse("tenant-a").unwrap(),
            EntityId::parse("repository-1").unwrap(),
            EntityKind::Repository,
            "repository",
        )
        .unwrap();
        let group = Entity::canonical(
            TenantId::parse("tenant-a").unwrap(),
            EntityId::parse("group-1").unwrap(),
            EntityKind::Group,
            "group",
        )
        .unwrap();

        assert_eq!(
            RelationshipAssertion::new(
                &repository,
                RelationKind::MemberOf,
                &group,
                provenance(receipt.receipt()),
                10,
            ),
            Err(ModelError::InvalidRelationship)
        );
    }

    #[test]
    fn complete_collection_can_retract_missing_assertions() {
        let mut builder = receipt().begin_delta();
        builder
            .retract_missing(
                AssertionId::parse("assertion-old").unwrap(),
                "absent from complete okta.users collection",
            )
            .unwrap();
        assert_eq!(builder.build().retractions().len(), 1);
    }

    #[test]
    fn invalid_values_cannot_enter_the_model_by_deserialization() {
        fn assert_serialize<T: Serialize>() {}
        assert_serialize::<GraphDelta>();
        // Validated domain values intentionally have no Deserialize bound.
    }

    #[test]
    fn validated_values_receipts_and_errors_expose_the_sealed_contract() {
        for value in [
            TenantId::parse("tenant-a").unwrap().to_string(),
            SourceRuntimeId::parse("okta-prod").unwrap().to_string(),
            CollectionId::parse("collection-1").unwrap().to_string(),
            ObservationId::parse("observation-1").unwrap().to_string(),
            EntityId::parse("entity-1").unwrap().to_string(),
            AssertionId::parse("assertion-1").unwrap().to_string(),
            CanonicalIdentityId::parse("person-1").unwrap().to_string(),
        ] {
            assert!(!value.is_empty());
        }
        assert_eq!(TenantId::parse(""), Err(ModelError::Empty("tenant id")));
        assert_eq!(
            TenantId::parse(" tenant"),
            Err(ModelError::Invalid("tenant id"))
        );
        assert_eq!(
            ProviderKind::parse("user"),
            Err(ModelError::Invalid("provider entity kind"))
        );
        assert_eq!(
            EntityId::parse("a".repeat(MAX_ID_BYTES + 1)),
            Err(ModelError::Invalid("entity id"))
        );

        let tenant = TenantId::parse("tenant-a").unwrap();
        let runtime = SourceRuntimeId::parse("okta-prod").unwrap();
        let collection = CollectionId::parse("collection-1").unwrap();
        let partial = CollectionReceipt::partial(
            tenant.clone(),
            runtime.clone(),
            collection.clone(),
            "okta.users",
            10,
        )
        .unwrap();
        assert_eq!(partial.tenant_id(), &tenant);
        assert_eq!(partial.source_runtime_id(), &runtime);
        assert_eq!(partial.collection_id(), &collection);
        assert_eq!(partial.scope(), "okta.users");
        assert_eq!(partial.observed_at_unix_ms(), 10);
        assert_eq!(partial.completeness(), &CollectionCompleteness::Partial);
        assert!(
            partial
                .clone()
                .begin_delta()
                .build()
                .digest()
                .starts_with("sha256:")
        );

        let incremental =
            CollectionReceipt::incremental(tenant, runtime, collection, "okta.users", 11).unwrap();
        assert_eq!(
            incremental.completeness(),
            &CollectionCompleteness::Incremental
        );
        assert_eq!(
            CollectionReceipt::partial(
                TenantId::parse("tenant-a").unwrap(),
                SourceRuntimeId::parse("okta-prod").unwrap(),
                CollectionId::parse("collection-1").unwrap(),
                "scope",
                0,
            ),
            Err(ModelError::Invalid("collection observed time"))
        );

        let messages = [
            ModelError::Empty("field"),
            ModelError::Invalid("field"),
            ModelError::TooLong("field"),
            ModelError::TenantMismatch,
            ModelError::CollectionMismatch,
            ModelError::InvalidRelationship,
            ModelError::InvalidIdentityBinding,
            ModelError::EvidenceRequired,
            ModelError::DuplicateEntity,
            ModelError::DuplicateAssertion,
        ]
        .map(|error| error.to_string());
        assert!(messages.iter().all(|message| !message.is_empty()));
    }

    #[test]
    fn every_typed_relationship_accepts_its_declared_endpoints() {
        let tenant = TenantId::parse("tenant-a").unwrap();
        let entity = |id: &str, kind: EntityKind| {
            Entity::canonical(tenant.clone(), EntityId::parse(id).unwrap(), kind, id).unwrap()
        };
        let person = entity("person", EntityKind::Person);
        let identity = entity("identity", EntityKind::Identity);
        let team = entity("team", EntityKind::Team);
        let organization = entity("organization", EntityKind::Organization);
        let repository = entity("repository", EntityKind::Repository);
        let service = entity("service", EntityKind::Service);
        let application = entity("application", EntityKind::Application);
        let environment = entity("environment", EntityKind::Environment);
        let account = entity("account", EntityKind::Account);
        let resource = entity("resource", EntityKind::Resource);
        let group = entity("group", EntityKind::Group);
        let role = entity("role", EntityKind::Role);
        let policy = entity("policy", EntityKind::Policy);
        let control = entity("control", EntityKind::Control);
        let finding = entity("finding", EntityKind::Finding);
        let framework = entity("framework", EntityKind::Framework);
        let program = entity("program", EntityKind::Program);
        let objective = entity("objective", EntityKind::Objective);
        let rule = entity("rule", EntityKind::Rule);
        let evidence = entity("evidence", EntityKind::Evidence);
        let assessment_run = entity("assessment-run", EntityKind::AssessmentRun);
        let assessment_result = entity("assessment-result", EntityKind::AssessmentResult);
        let assessment_snapshot = entity("assessment-snapshot", EntityKind::AssessmentSnapshot);
        let remediation = entity("remediation", EntityKind::Remediation);
        let verification = entity("verification", EntityKind::Verification);
        let work_item = entity("work-item", EntityKind::WorkItem);
        let provider = entity(
            "provider",
            EntityKind::Provider(ProviderKind::parse("github.repository").unwrap()),
        );
        let cases = [
            (RelationKind::MemberOf, &identity, &group, "member_of"),
            (RelationKind::Owns, &person, &repository, "owns"),
            (RelationKind::Maintains, &team, &service, "maintains"),
            (
                RelationKind::DependsOn,
                &service,
                &application,
                "depends_on",
            ),
            (RelationKind::Builds, &repository, &service, "builds"),
            (RelationKind::Deploys, &service, &environment, "deploys"),
            (RelationKind::RunsIn, &resource, &account, "runs_in"),
            (RelationKind::Contains, &organization, &resource, "contains"),
            (RelationKind::CanAssume, &identity, &role, "can_assume"),
            (
                RelationKind::CanAccess,
                &application,
                &resource,
                "can_access",
            ),
            (RelationKind::Grants, &policy, &account, "grants"),
            (RelationKind::ProvisionedAs, &group, &team, "provisioned_as"),
            (RelationKind::Governs, &control, &service, "governs"),
            (RelationKind::Affects, &finding, &resource, "affects"),
            (RelationKind::Supports, &account, &application, "supports"),
            (
                RelationKind::EvidenceFor,
                &resource,
                &finding,
                "evidence_for",
            ),
            (
                RelationKind::MappedToControl,
                &finding,
                &control,
                "mapped_to_control",
            ),
            (RelationKind::TrackedBy, &resource, &provider, "tracked_by"),
            (RelationKind::Implements, &policy, &control, "implements"),
            (RelationKind::Tests, &rule, &objective, "tests"),
            (RelationKind::Includes, &framework, &control, "includes"),
            (RelationKind::Scopes, &program, &resource, "scopes"),
            (RelationKind::Uses, &assessment_run, &program, "uses"),
            (
                RelationKind::Evaluates,
                &assessment_result,
                &objective,
                "evaluates",
            ),
            (
                RelationKind::Assesses,
                &assessment_result,
                &resource,
                "assesses",
            ),
            (RelationKind::Cites, &assessment_result, &evidence, "cites"),
            (RelationKind::DetectedBy, &finding, &rule, "detected_by"),
            (RelationKind::Addresses, &remediation, &finding, "addresses"),
            (
                RelationKind::Verifies,
                &verification,
                &remediation,
                "verifies",
            ),
            (
                RelationKind::Commits,
                &assessment_snapshot,
                &assessment_result,
                "commits",
            ),
            (
                RelationKind::DerivedFrom,
                &finding,
                &work_item,
                "derived_from",
            ),
        ];
        let collection = receipt();
        for (relation, from, to, name) in cases {
            let assertion = RelationshipAssertion::new(
                from,
                relation,
                to,
                provenance(collection.receipt()),
                10,
            )
            .unwrap();
            assert_eq!(relation.as_str(), name);
            assert_eq!(assertion.tenant_id(), &tenant);
            assert_eq!(assertion.from(), from.id());
            assert_eq!(assertion.to(), to.id());
            assert_eq!(assertion.relation(), relation);
            assert_eq!(assertion.observed_at_unix_ms(), 10);
            assert_eq!(assertion.provenance().producer(), "okta-user-mapper");
        }

        assert_eq!(
            RelationshipAssertion::new(
                &person,
                RelationKind::Verifies,
                &finding,
                provenance(collection.receipt()),
                10,
            ),
            Err(ModelError::InvalidRelationship)
        );
    }

    #[test]
    fn authoritative_delta_preserves_identity_evidence_and_retractions() {
        let collection = receipt();
        let receipt = collection.receipt();
        let observation = ObservationRef::new(
            receipt,
            ObservationId::parse("observation-2").unwrap(),
            "okta.user:00u2",
        )
        .unwrap();
        assert_eq!(observation.tenant_id(), receipt.tenant_id());
        assert_eq!(observation.source_runtime_id(), receipt.source_runtime_id());
        assert_eq!(observation.collection_id(), receipt.collection_id());
        assert_eq!(observation.source_record(), "okta.user:00u2");
        let evidence =
            AssertionProvenance::direct(vec![observation], "identity-mapper", "v2").unwrap();
        assert_eq!(evidence.observations().len(), 1);
        assert_eq!(evidence.producer(), "identity-mapper");
        assert_eq!(evidence.producer_version(), "v2");

        let claim = IdentityClaim::employee_id("E-123").unwrap();
        assert_eq!(claim.kind(), IdentityClaimKind::EmployeeId);
        assert_eq!(claim.value(), "E-123");
        assert_eq!(IdentityClaimKind::EmployeeId.as_str(), "employee_id");
        assert_eq!(IdentityClaimKind::VerifiedEmail.as_str(), "verified_email");
        let canonical =
            CanonicalIdentity::for_claim(receipt.tenant_id().clone(), &claim, "A Person").unwrap();
        let provider = ProviderIdentity::new(
            receipt.tenant_id().clone(),
            receipt.source_runtime_id().clone(),
            ProviderKind::parse("okta.user").unwrap(),
            "00u2",
            "A Person",
        )
        .unwrap();
        let binding = IdentityBindingAssertion::new(
            &provider,
            &canonical,
            IdentityResolutionMethod::AuthoritativeEmployeeId,
            Some(claim.clone()),
            IdentityBindingState::Confirmed,
            evidence,
            10,
        )
        .unwrap();
        assert_eq!(binding.tenant_id(), receipt.tenant_id());
        assert_eq!(binding.provider_identity(), provider.entity().id());
        assert_eq!(binding.canonical_identity(), canonical.entity().id());
        assert_eq!(
            binding.method(),
            IdentityResolutionMethod::AuthoritativeEmployeeId
        );
        assert_eq!(binding.provider_kind().as_str(), "okta.user");
        assert_eq!(binding.claim(), Some(&claim));
        assert_eq!(binding.state(), IdentityBindingState::Confirmed);
        assert_eq!(binding.observed_at_unix_ms(), 10);

        let tenant_id = receipt.tenant_id().clone();
        let mut builder = collection.begin_delta();
        builder.add_entity(provider.clone().into_entity()).unwrap();
        builder.add_entity(canonical.clone().into_entity()).unwrap();
        let assertion = GraphAssertion::IdentityBinding(binding);
        assert_eq!(assertion.tenant_id(), &tenant_id);
        builder.add_assertion(assertion.clone()).unwrap();
        builder.add_assertion(assertion).unwrap();
        builder
            .retract_missing(
                AssertionId::parse("assertion-old").unwrap(),
                "no longer observed",
            )
            .unwrap();
        let delta = builder.build();
        assert_eq!(delta.entities().len(), 2);
        assert_eq!(delta.assertions().len(), 1);
        assert_eq!(delta.retractions().len(), 1);
        assert_eq!(delta.retractions()[0].reason(), "no longer observed");
        assert_eq!(
            delta.retractions()[0].assertion_id().as_str(),
            "assertion-old"
        );
        let (receipt, entities, assertions, retractions, digest) = delta.into_components();
        assert_eq!(receipt.completeness(), &CollectionCompleteness::Complete);
        assert_eq!(entities.len(), 2);
        assert_eq!(assertions.len(), 1);
        assert_eq!(retractions.len(), 1);
        assert!(digest.starts_with("sha256:"));
    }

    #[test]
    fn delta_builder_rejects_cross_tenant_and_conflicting_values() {
        let mut builder = receipt().begin_delta();
        let first = Entity::canonical(
            TenantId::parse("tenant-a").unwrap(),
            EntityId::parse("entity-1").unwrap(),
            EntityKind::Resource,
            "first",
        )
        .unwrap();
        let conflicting = Entity::canonical(
            TenantId::parse("tenant-a").unwrap(),
            EntityId::parse("entity-1").unwrap(),
            EntityKind::Resource,
            "second",
        )
        .unwrap();
        builder.add_entity(first.clone()).unwrap();
        builder.add_entity(first).unwrap();
        assert_eq!(
            builder.add_entity(conflicting),
            Err(ModelError::DuplicateEntity)
        );
        assert_eq!(
            builder.add_entity(
                Entity::canonical(
                    TenantId::parse("tenant-b").unwrap(),
                    EntityId::parse("entity-2").unwrap(),
                    EntityKind::Resource,
                    "other",
                )
                .unwrap(),
            ),
            Err(ModelError::TenantMismatch)
        );
        assert_eq!(
            AssertionProvenance::direct(Vec::new(), "mapper", "v1"),
            Err(ModelError::EvidenceRequired)
        );
    }

    #[test]
    fn delta_order_and_digest_do_not_depend_on_insertion_order() {
        let collection = receipt();
        let first = Entity::canonical(
            TenantId::parse("tenant-a").unwrap(),
            EntityId::parse("entity-1").unwrap(),
            EntityKind::Resource,
            "first",
        )
        .unwrap();
        let second = Entity::canonical(
            TenantId::parse("tenant-a").unwrap(),
            EntityId::parse("entity-2").unwrap(),
            EntityKind::Resource,
            "second",
        )
        .unwrap();

        let mut forward = collection.clone().begin_delta();
        forward.add_entity(first.clone()).unwrap();
        forward.add_entity(second.clone()).unwrap();
        let forward = forward.build();

        let mut reverse = collection.begin_delta();
        reverse.add_entity(second).unwrap();
        reverse.add_entity(first).unwrap();
        let reverse = reverse.build();

        assert_eq!(forward.digest(), reverse.digest());
        assert_eq!(forward.entities(), reverse.entities());
        assert_eq!(forward.entities()[0].id().as_str(), "entity-1");
    }
}
