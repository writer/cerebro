#![forbid(unsafe_code)]

//! The sealed domain model for Cerebro's organizational graph.
//!
//! Validated values deliberately do not implement `Deserialize`. External data
//! must cross an admission boundary and use the constructors in this crate.

use std::{collections::BTreeMap, error::Error, fmt};

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
    Provider(ProviderKind),
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

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn properties(&self) -> &BTreeMap<String, String> {
        &self.properties
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
        }
    }

    fn accepts(self, from: &EntityKind, to: &EntityKind) -> bool {
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
    entities: BTreeMap<EntityId, Entity>,
    assertions: BTreeMap<AssertionId, GraphAssertion>,
    retractions: BTreeMap<AssertionId, Retraction>,
    _mode: std::marker::PhantomData<Mode>,
}

impl<Mode> GraphDeltaBuilder<Mode> {
    fn new(collection: CollectionReceipt) -> Self {
        Self {
            collection,
            entities: BTreeMap::new(),
            assertions: BTreeMap::new(),
            retractions: BTreeMap::new(),
            _mode: std::marker::PhantomData,
        }
    }

    pub fn add_entity(&mut self, entity: Entity) -> Result<(), ModelError> {
        if entity.tenant_id != self.collection.tenant_id {
            return Err(ModelError::TenantMismatch);
        }
        match self.entities.entry(entity.id.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(entity);
            }
            std::collections::btree_map::Entry::Occupied(entry) if entry.get() != &entity => {
                return Err(ModelError::DuplicateEntity);
            }
            std::collections::btree_map::Entry::Occupied(_) => {}
        }
        Ok(())
    }

    pub fn add_assertion(&mut self, assertion: GraphAssertion) -> Result<(), ModelError> {
        if assertion.tenant_id() != &self.collection.tenant_id
            || assertion.provenance().source_runtime_id() != &self.collection.source_runtime_id
        {
            return Err(ModelError::TenantMismatch);
        }
        match self.assertions.entry(assertion.id().clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(assertion);
            }
            std::collections::btree_map::Entry::Occupied(entry) if entry.get() != &assertion => {
                return Err(ModelError::DuplicateAssertion);
            }
            std::collections::btree_map::Entry::Occupied(_) => {}
        }
        Ok(())
    }

    pub fn build(self) -> GraphDelta {
        let entities: Vec<_> = self.entities.into_values().collect();
        let assertions: Vec<_> = self.assertions.into_values().collect();
        let retractions: Vec<_> = self.retractions.into_values().collect();
        let digest = delta_digest(&self.collection, &entities, &assertions, &retractions);
        GraphDelta {
            collection: self.collection,
            entities,
            assertions,
            retractions,
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
        self.retractions.insert(
            assertion_id.clone(),
            Retraction {
                assertion_id,
                reason: validate_text(reason.into(), "retraction reason")?,
            },
        );
        Ok(())
    }
}

fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    let digest = hex_digest(hasher.finalize().as_slice());
    format!("{prefix}:{}", &digest[..32])
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
    format!("sha256:{}", hex_digest(hasher.finalize().as_slice()))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
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
}
