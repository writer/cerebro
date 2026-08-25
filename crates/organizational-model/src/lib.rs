#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Sealed admission model for Cerebro's organizational graph.
//!
//! This crate owns the values that may cross from a source adapter into the
//! graph engine: tenant-scoped entities, evidence-backed assertions, collection
//! receipts, and deterministic deltas. Constructors validate identifiers,
//! tenant boundaries, evidence collection consistency, relationship endpoints,
//! identity-binding authority, and collection completeness before a value can
//! be serialized.
//!
//! # Authority boundary
//!
//! Validated values deliberately do not implement `serde::Deserialize`.
//! External records are observations, not graph facts, and must cross an
//! explicit constructor in this crate. This prevents a provider payload or a
//! persisted JSON document from bypassing the model's admission checks.
//!
//! Partial and incremental receipts create [`NonAuthoritative`] delta builders.
//! Only a [`CompleteCollection`] creates an [`Authoritative`] builder capable of
//! retracting assertions that are absent from a complete source snapshot. A
//! complete receipt is therefore a source-coverage claim, not merely a batch
//! label.
//!
//! # Stable output
//!
//! Provider entity and assertion identifiers are derived deterministically from
//! their sealed identity fields. [`GraphDeltaBuilder::build`] sorts admitted
//! values before computing a digest, so input order does not change the emitted
//! delta. Labels and properties remain mutable presentation data and do not
//! participate in entity identity.

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
/// A rejected organizational-model value or operation.
pub enum ModelError {
    /// A required field was empty.
    Empty(&'static str),
    /// A field failed its syntax or semantic validation.
    Invalid(&'static str),
    /// A field exceeded the model's encoded-size limit.
    TooLong(&'static str),
    /// Values from different tenants were combined.
    TenantMismatch,
    /// Evidence references did not belong to one collection.
    CollectionMismatch,
    /// A relationship used invalid endpoint kinds or observation time.
    InvalidRelationship,
    /// An identity binding violated its authority, claim, or state rules.
    InvalidIdentityBinding,
    /// An assertion was created without an observation.
    EvidenceRequired,
    /// One delta assigned conflicting representations to the same entity ID.
    DuplicateEntity,
    /// One delta assigned conflicting representations to the same assertion ID.
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
        #[doc = concat!("A validated ", $field, ".")]
        ///
        /// Identifiers are non-empty, have no surrounding whitespace, contain
        /// at most 256 bytes, and use only ASCII letters, digits, `-`, `_`, `.`,
        /// `:`, or `/`.
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Validates and constructs a ", $field, ".")]
            ///
            /// # Errors
            ///
            /// Returns [`ModelError::Empty`] or [`ModelError::Invalid`] when
            /// the value violates the identifier contract.
            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                Ok(Self(validate_identifier(value.into(), $field)?))
            }

            #[doc = concat!("Returns the validated ", $field, " as text.")]
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
/// A provider-specific entity kind such as `okta.user`.
///
/// Provider kinds require a dotted namespace so they cannot be confused with
/// the fixed kinds in [`EntityKind`].
pub struct ProviderKind(String);

impl ProviderKind {
    /// Validates a provider-specific kind.
    ///
    /// # Errors
    ///
    /// Returns a model error unless the value is a valid identifier containing
    /// at least one `.` separator.
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = validate_identifier(value.into(), "provider entity kind")?;
        if !value.contains('.') {
            return Err(ModelError::Invalid("provider entity kind"));
        }
        Ok(Self(value))
    }

    /// Returns the provider kind's wire value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
/// The semantic role of an entity in the organizational graph.
pub enum EntityKind {
    /// A canonical human identity.
    Person,
    /// An identity projected from an external provider.
    Identity,
    /// A working team.
    Team,
    /// An organization or company boundary.
    Organization,
    /// A source-code repository.
    Repository,
    /// A deployed or deployable service.
    Service,
    /// A user-facing or internal application.
    Application,
    /// A deployment environment.
    Environment,
    /// A provider or cloud account.
    Account,
    /// A provider-managed resource.
    Resource,
    /// A provider or directory group.
    Group,
    /// An assumable or assignable role.
    Role,
    /// A policy statement or document.
    Policy,
    /// A security or compliance control.
    Control,
    /// A detected security or compliance finding.
    Finding,
    /// A control framework.
    Framework,
    /// A governed assessment or assurance program.
    Program,
    /// An assessment objective.
    Objective,
    /// An executable or declarative assessment rule.
    Rule,
    /// Evidence supporting an assessment or finding.
    Evidence,
    /// One execution of an assessment program.
    AssessmentRun,
    /// The result of evaluating one assessment target.
    AssessmentResult,
    /// An immutable snapshot committed by an assessment.
    AssessmentSnapshot,
    /// A remediation that addresses a finding.
    Remediation,
    /// Independent evidence that a remediation or finding was checked.
    Verification,
    /// A tracked unit of remediation work.
    WorkItem,
    /// A namespaced provider extension not represented by a fixed kind.
    Provider(ProviderKind),
}

impl EntityKind {
    /// Returns the stable wire category for this kind.
    ///
    /// All [`EntityKind::Provider`] values return `provider`; use the nested
    /// [`ProviderKind`] to distinguish provider extensions.
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

    /// Returns whether `value` is a recognized top-level entity-kind wire name.
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
/// The system allowed to define an entity's stable identity.
pub enum EntityAuthority {
    /// Cerebro owns the stable identity directly.
    Canonical,
    /// An external runtime owns the stable identity.
    Provider {
        /// Runtime instance that observed the provider record.
        source_runtime_id: SourceRuntimeId,
        /// Provider-specific record kind.
        provider_kind: ProviderKind,
        /// Provider's native stable identifier.
        provider_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// A validated, tenant-scoped organizational graph entity.
///
/// Stable identity consists of the ID, tenant, kind, and authority. The label
/// and properties may change when a source refreshes presentation data.
pub struct Entity {
    id: EntityId,
    tenant_id: TenantId,
    kind: EntityKind,
    authority: EntityAuthority,
    label: String,
    properties: BTreeMap<String, String>,
}

impl Entity {
    /// Constructs an entity whose stable identity Cerebro owns.
    ///
    /// # Errors
    ///
    /// Returns a model error when `label` is empty, untrimmed, contains a
    /// control character, or exceeds 1,024 bytes.
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

    /// Constructs an entity whose stable identity an external provider owns.
    ///
    /// The entity ID is derived from the tenant, runtime, provider kind, and
    /// native provider ID; mutable labels and properties do not affect it.
    ///
    /// # Errors
    ///
    /// Returns a model error when the provider ID or label violates the text
    /// contract, or when the derived ID cannot be admitted.
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

    /// Adds or replaces one validated presentation property.
    ///
    /// # Errors
    ///
    /// Returns a model error when the key is not a valid identifier or the
    /// value violates the model's text contract.
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

    /// Returns the entity's tenant-local stable ID.
    pub fn id(&self) -> &EntityId {
        &self.id
    }

    /// Returns the tenant that owns this entity.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the entity's semantic graph kind.
    pub fn kind(&self) -> &EntityKind {
        &self.kind
    }

    /// Returns the authority that owns the entity's stable identity.
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

    /// Returns the mutable display label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the validated presentation properties in deterministic key order.
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
/// A Cerebro-owned person identity.
///
/// The wrapper prevents a general canonical entity from being used where an
/// identity-binding constructor requires a canonical person endpoint.
pub struct CanonicalIdentity(Entity);

impl CanonicalIdentity {
    /// Constructs a canonical person from an explicit canonical identity ID.
    ///
    /// # Errors
    ///
    /// Returns a model error when the derived entity ID or label is invalid.
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

    /// Constructs the deterministic canonical person for a verified claim.
    ///
    /// Claim kind and normalized value participate in the ID, scoped by tenant.
    ///
    /// # Errors
    ///
    /// Returns a model error when the derived identifiers or label are invalid.
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

    /// Borrows the sealed person entity.
    pub fn entity(&self) -> &Entity {
        &self.0
    }

    /// Consumes the identity wrapper and returns its sealed entity.
    pub fn into_entity(self) -> Entity {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// An identity record owned by an external provider runtime.
///
/// The wrapper proves that an identity-binding endpoint was constructed as a
/// provider-owned [`EntityKind::Identity`].
pub struct ProviderIdentity(Entity);

impl ProviderIdentity {
    /// Constructs a provider-owned identity record.
    ///
    /// # Errors
    ///
    /// Returns a model error when the provider ID, label, or derived entity ID
    /// violates the model contract.
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

    /// Borrows the sealed provider identity entity.
    pub fn entity(&self) -> &Entity {
        &self.0
    }

    /// Consumes the identity wrapper and returns its sealed entity.
    pub fn into_entity(self) -> Entity {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// How much of a declared source scope a collection receipt observed.
pub enum CollectionCompleteness {
    /// The collection covers an explicitly incomplete subset of its scope.
    Partial,
    /// The collection contains changes since an earlier source position.
    Incremental,
    /// The collection covers the entire declared scope at its observation time.
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Evidence that one source runtime collected a declared tenant scope.
///
/// Partial and incremental receipts can add or refresh facts but cannot prove
/// that a missing fact was removed at the source.
pub struct CollectionReceipt {
    tenant_id: TenantId,
    source_runtime_id: SourceRuntimeId,
    collection_id: CollectionId,
    scope: String,
    completeness: CollectionCompleteness,
    observed_at_unix_ms: i64,
}

impl CollectionReceipt {
    /// Creates a receipt for an incomplete observation of the declared scope.
    ///
    /// # Errors
    ///
    /// Returns a model error when the scope is invalid or the observation time
    /// is not a positive Unix timestamp in milliseconds.
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

    /// Creates a receipt containing changes since an earlier source position.
    ///
    /// # Errors
    ///
    /// Returns a model error when the scope is invalid or the observation time
    /// is not a positive Unix timestamp in milliseconds.
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

    /// Returns the tenant whose source scope was collected.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the runtime instance that performed the collection.
    pub fn source_runtime_id(&self) -> &SourceRuntimeId {
        &self.source_runtime_id
    }

    /// Returns the collection attempt's stable ID.
    pub fn collection_id(&self) -> &CollectionId {
        &self.collection_id
    }

    /// Returns the source's coverage claim for this collection.
    pub fn completeness(&self) -> &CollectionCompleteness {
        &self.completeness
    }

    /// Returns the source-defined scope covered by this receipt.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Returns when the source scope was observed, as Unix milliseconds.
    pub fn observed_at_unix_ms(&self) -> i64 {
        self.observed_at_unix_ms
    }

    /// Starts a delta that may add facts but cannot retract missing assertions.
    pub fn begin_delta(self) -> GraphDeltaBuilder<NonAuthoritative> {
        GraphDeltaBuilder::new(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// A receipt proving complete coverage of its declared source scope.
///
/// This separate type is the capability required to construct an
/// [`Authoritative`] delta builder and express source-authoritative removals.
pub struct CompleteCollection(CollectionReceipt);

impl CompleteCollection {
    /// Creates a receipt for complete coverage of the declared source scope.
    ///
    /// # Errors
    ///
    /// Returns a model error when the scope is invalid or the observation time
    /// is not a positive Unix timestamp in milliseconds.
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

    /// Borrows the underlying collection receipt.
    pub fn receipt(&self) -> &CollectionReceipt {
        &self.0
    }

    /// Starts a delta authorized to retract assertions missing from the scope.
    pub fn begin_delta(self) -> GraphDeltaBuilder<Authoritative> {
        GraphDeltaBuilder::new(self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// A source record that directly supports an assertion.
///
/// Observation references inherit tenant, runtime, and collection identity
/// from a receipt so callers cannot independently combine those coordinates.
pub struct ObservationRef {
    observation_id: ObservationId,
    tenant_id: TenantId,
    source_runtime_id: SourceRuntimeId,
    collection_id: CollectionId,
    source_record: String,
}

impl ObservationRef {
    /// Attaches one source record to a collection receipt.
    ///
    /// # Errors
    ///
    /// Returns a model error when `source_record` violates the text contract.
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

    /// Returns the tenant inherited from the collection receipt.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the stable ID of this observation.
    pub fn observation_id(&self) -> &ObservationId {
        &self.observation_id
    }

    /// Returns the runtime inherited from the collection receipt.
    pub fn source_runtime_id(&self) -> &SourceRuntimeId {
        &self.source_runtime_id
    }

    /// Returns the collection inherited from the collection receipt.
    pub fn collection_id(&self) -> &CollectionId {
        &self.collection_id
    }

    /// Returns the source-native record locator or identifier.
    pub fn source_record(&self) -> &str {
        &self.source_record
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Direct evidence and producer identity for one admitted assertion.
///
/// Every observation must come from the same tenant, runtime, and collection.
pub struct AssertionProvenance {
    observations: Vec<ObservationRef>,
    producer: String,
    producer_version: String,
}

impl AssertionProvenance {
    /// Constructs provenance from one or more direct source observations.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::EvidenceRequired`] for an empty observation set,
    /// [`ModelError::CollectionMismatch`] when observations cross collection
    /// coordinates, or a validation error for either producer identifier.
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

    /// Returns the tenant shared by all observations.
    pub fn tenant_id(&self) -> &TenantId {
        &self.observations[0].tenant_id
    }

    /// Returns the source runtime shared by all observations.
    pub fn source_runtime_id(&self) -> &SourceRuntimeId {
        &self.observations[0].source_runtime_id
    }

    /// Returns the direct observations supporting the assertion.
    pub fn observations(&self) -> &[ObservationRef] {
        &self.observations
    }

    /// Returns the component that produced the assertion.
    pub fn producer(&self) -> &str {
        &self.producer
    }

    /// Returns the producing component's version.
    pub fn producer_version(&self) -> &str {
        &self.producer_version
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
/// A validated semantic edge between two organizational entities.
///
/// Each relation admits a bounded set of endpoint kinds through
/// [`RelationKind::accepts`].
pub enum RelationKind {
    /// A person or identity belongs to a group or team.
    MemberOf,
    /// A person, team, or organization owns an operational object.
    Owns,
    /// A person, team, or organization maintains an operational object.
    Maintains,
    /// One non-finding object depends on another.
    DependsOn,
    /// A repository builds a service or application.
    Builds,
    /// A repository or service deploys into an environment.
    Deploys,
    /// A service, application, or resource runs in an environment or account.
    RunsIn,
    /// An organization, account, environment, or group contains another object.
    Contains,
    /// An identity or role can assume a role.
    CanAssume,
    /// An identity, principal, application, or service can access an asset.
    CanAccess,
    /// A group, team, role, or policy grants access to an object.
    Grants,
    /// A provider group is provisioned as a team, role, or group.
    ProvisionedAs,
    /// A policy or control governs an object.
    Governs,
    /// A finding affects an object.
    Affects,
    /// An object supports a service, application, or control.
    Supports,
    /// An object supplies evidence for a finding or control.
    EvidenceFor,
    /// A finding or policy maps to a control.
    MappedToControl,
    /// An object is tracked by a provider-specific record.
    TrackedBy,
    /// A policy implements a control.
    Implements,
    /// A rule tests an assessment objective.
    Tests,
    /// A framework or program includes a governed definition.
    Includes,
    /// A program scopes an assessable organizational object.
    Scopes,
    /// An assessment run uses a program, policy, rule, or snapshot.
    Uses,
    /// An assessment result evaluates an objective or control.
    Evaluates,
    /// An assessment result assesses an operational target.
    Assesses,
    /// A finding or assessment artifact cites evidence.
    Cites,
    /// A rule detected a finding.
    DetectedBy,
    /// A remediation or work item addresses a finding.
    Addresses,
    /// A verification checks a remediation or finding.
    Verifies,
    /// An assessment snapshot commits to an assessment result.
    Commits,
    /// A finding, assessment result, or verification derives from another object.
    DerivedFrom,
}

impl RelationKind {
    /// Returns the stable snake-case wire name.
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

    /// Parses a stable snake-case wire name.
    ///
    /// Returns `None` for unknown names so callers must reject or explicitly
    /// map provider extensions rather than silently creating a relation.
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

    /// Returns whether this relation admits the supplied endpoint kinds.
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

fn entity_application_workspace_id(entity: &Entity) -> &str {
    entity
        .properties()
        .get("application_workspace_id")
        .map(String::as_str)
        .unwrap_or_default()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// An evidence-backed, directed relationship between two sealed entities.
pub struct RelationshipAssertion {
    id: AssertionId,
    tenant_id: TenantId,
    from: EntityId,
    from_kind: EntityKind,
    relation: RelationKind,
    to: EntityId,
    to_kind: EntityKind,
    #[serde(skip_serializing)]
    application_workspace_id: String,
    provenance: AssertionProvenance,
    observed_at_unix_ms: i64,
}

impl RelationshipAssertion {
    /// Constructs a relationship assertion from sealed endpoints and evidence.
    ///
    /// The ID is deterministic across tenant, endpoints, relation, and source
    /// runtime. Observation time must be a positive Unix timestamp in
    /// milliseconds.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::TenantMismatch`] when endpoints or evidence cross
    /// tenants, or [`ModelError::InvalidRelationship`] when endpoint kinds are
    /// not admitted or the observation time is invalid.
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
        let from_workspace = entity_application_workspace_id(from);
        let to_workspace = entity_application_workspace_id(to);
        if !relation.accepts(&from.kind, &to.kind)
            || observed_at_unix_ms <= 0
            || from_workspace != to_workspace
        {
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
            application_workspace_id: from_workspace.to_owned(),
            provenance,
            observed_at_unix_ms,
        })
    }

    /// Returns the assertion's deterministic stable ID.
    pub fn id(&self) -> &AssertionId {
        &self.id
    }

    /// Returns the tenant shared by both endpoints and the evidence.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the source endpoint entity ID.
    pub fn from(&self) -> &EntityId {
        &self.from
    }

    /// Returns the destination endpoint entity ID.
    pub fn to(&self) -> &EntityId {
        &self.to
    }

    /// Returns the trusted application workspace shared by both endpoints.
    pub fn application_workspace_id(&self) -> &str {
        &self.application_workspace_id
    }

    /// Returns the admitted relationship kind.
    pub fn relation(&self) -> RelationKind {
        self.relation
    }

    /// Returns the direct source provenance.
    pub fn provenance(&self) -> &AssertionProvenance {
        &self.provenance
    }

    /// Returns when the relationship was observed, as Unix milliseconds.
    pub fn observed_at_unix_ms(&self) -> i64 {
        self.observed_at_unix_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
/// The authority or workflow used to resolve a provider identity.
pub enum IdentityResolutionMethod {
    /// An authoritative employee identifier produced the match.
    AuthoritativeEmployeeId,
    /// A verified email address produced the match.
    VerifiedEmail,
    /// A previously established claim produced the match.
    ExistingClaimMatch,
    /// A human explicitly decided the match.
    HumanDecision,
    /// An agent proposed a match that still requires another authority.
    AgentProposal,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
/// The normalized claim used to correlate identities.
pub enum IdentityClaimKind {
    /// An employee identifier from an authoritative workforce source.
    EmployeeId,
    /// An email address whose ownership was verified.
    VerifiedEmail,
}

impl IdentityClaimKind {
    /// Returns the stable snake-case wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmployeeId => "employee_id",
            Self::VerifiedEmail => "verified_email",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// A validated identity-correlation claim.
pub struct IdentityClaim {
    kind: IdentityClaimKind,
    value: String,
}

impl IdentityClaim {
    /// Constructs an employee-ID claim.
    ///
    /// # Errors
    ///
    /// Returns a model error when the value violates the text contract.
    pub fn employee_id(value: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self {
            kind: IdentityClaimKind::EmployeeId,
            value: validate_text(value.into(), "employee id")?,
        })
    }

    /// Constructs and lowercases a minimally valid verified-email claim.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Invalid`] unless the value contains non-empty
    /// local and dotted-domain parts, or another text-validation error.
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

    /// Returns the claim's correlation kind.
    pub fn kind(&self) -> IdentityClaimKind {
        self.kind
    }

    /// Returns the normalized claim value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// The decision state of a provider-to-canonical identity binding.
pub enum IdentityBindingState {
    /// A candidate match awaiting an authoritative decision.
    Proposed,
    /// A match admitted under the method-specific authority rules.
    Confirmed,
    /// A candidate explicitly determined not to match.
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// An evidence-backed decision relating one provider identity to one person.
///
/// Agent proposals cannot be confirmed. Confirmed employee-ID and verified-email
/// decisions are restricted to approved Okta identity provider kinds; confirmed
/// claims must also match the selected resolution method.
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
    /// Constructs and validates an identity-binding decision.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidIdentityBinding`] when tenant identity,
    /// observation time, endpoint authority, provider authority, claim kind, or
    /// decision state violates the binding rules. Derived ID failures are also
    /// returned as model errors.
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

    /// Returns the binding assertion's deterministic ID.
    pub fn id(&self) -> &AssertionId {
        &self.id
    }

    /// Returns the tenant shared by both identity endpoints and the evidence.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the provider-owned identity endpoint.
    pub fn provider_identity(&self) -> &EntityId {
        &self.provider_identity
    }

    /// Returns the Cerebro-owned canonical person endpoint.
    pub fn canonical_identity(&self) -> &EntityId {
        &self.canonical_identity
    }

    /// Returns the current decision state.
    pub fn state(&self) -> IdentityBindingState {
        self.state
    }

    /// Returns the authority or workflow used for the decision.
    pub fn method(&self) -> IdentityResolutionMethod {
        self.method
    }

    /// Returns the provider kind owning the provider identity.
    pub fn provider_kind(&self) -> &ProviderKind {
        &self.provider_kind
    }

    /// Returns the normalized correlation claim, when the decision has one.
    pub fn claim(&self) -> Option<&IdentityClaim> {
        self.claim.as_ref()
    }

    /// Returns the direct source provenance for this decision.
    pub fn provenance(&self) -> &AssertionProvenance {
        &self.provenance
    }

    /// Returns when the decision was observed, as Unix milliseconds.
    pub fn observed_at_unix_ms(&self) -> i64 {
        self.observed_at_unix_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "assertion_type", rename_all = "snake_case")]
/// A validated assertion admitted into an organizational graph delta.
pub enum GraphAssertion {
    /// A directed semantic edge between organizational entities.
    Relationship(RelationshipAssertion),
    /// A decision relating a provider identity to a canonical person.
    IdentityBinding(IdentityBindingAssertion),
}

impl GraphAssertion {
    /// Returns the assertion's deterministic ID.
    pub fn id(&self) -> &AssertionId {
        match self {
            Self::Relationship(value) => value.id(),
            Self::IdentityBinding(value) => value.id(),
        }
    }

    /// Returns the tenant that owns the assertion.
    pub fn tenant_id(&self) -> &TenantId {
        match self {
            Self::Relationship(value) => value.tenant_id(),
            Self::IdentityBinding(value) => value.tenant_id(),
        }
    }

    /// Returns the direct evidence and producer identity.
    pub fn provenance(&self) -> &AssertionProvenance {
        match self {
            Self::Relationship(value) => value.provenance(),
            Self::IdentityBinding(value) => value.provenance(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// An authoritative instruction to remove a previously admitted assertion.
///
/// Retractions have no public constructor and can only be created through
/// [`GraphDeltaBuilder<Authoritative>::retract_missing`].
pub struct Retraction {
    assertion_id: AssertionId,
    reason: String,
}

impl Retraction {
    /// Returns the stable ID of the assertion to remove.
    pub fn assertion_id(&self) -> &AssertionId {
        &self.assertion_id
    }

    /// Returns the source-authoritative reason the assertion is absent.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Marker proving a delta's collection did not cover its complete source scope.
///
/// Builders in this mode cannot create retractions.
pub struct NonAuthoritative;
/// Marker proving a delta's collection covered its complete declared scope.
///
/// Only builders in this mode can create source-authoritative retractions.
pub struct Authoritative;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// A deterministic batch of admitted graph changes from one collection.
///
/// Entities, assertions, and retractions are sorted by stable ID before the
/// digest is computed. The digest identifies model membership and collection
/// coordinates; it is not a signature or an authorization decision.
pub struct GraphDelta {
    collection: CollectionReceipt,
    entities: Vec<Entity>,
    assertions: Vec<GraphAssertion>,
    retractions: Vec<Retraction>,
    digest: String,
}

impl GraphDelta {
    /// Returns the collection receipt authorizing this delta.
    pub fn collection(&self) -> &CollectionReceipt {
        &self.collection
    }

    /// Returns the entities added or refreshed by this delta.
    pub fn entities(&self) -> &[Entity] {
        &self.entities
    }

    /// Returns the assertions added or refreshed by this delta.
    pub fn assertions(&self) -> &[GraphAssertion] {
        &self.assertions
    }

    /// Returns authoritative assertion removals in this delta.
    pub fn retractions(&self) -> &[Retraction] {
        &self.retractions
    }

    /// Returns the deterministic membership digest.
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

/// Builds one tenant- and runtime-scoped graph delta.
///
/// The `Mode` is supplied only by a collection receipt: partial and incremental
/// receipts yield [`NonAuthoritative`], while [`CompleteCollection`] yields
/// [`Authoritative`]. Duplicate identical values are idempotent; conflicting
/// values with the same stable ID are rejected.
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

    /// Adds an entity to the collection's tenant.
    ///
    /// Adding the same entity twice is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::TenantMismatch`] for a different tenant or
    /// [`ModelError::DuplicateEntity`] when the same ID has conflicting data.
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

    /// Adds an assertion from the collection's tenant and source runtime.
    ///
    /// Adding the same assertion twice is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::TenantMismatch`] for different tenant or runtime
    /// coordinates, or [`ModelError::DuplicateAssertion`] when the same ID has
    /// conflicting data.
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

    /// Sorts admitted values and returns a delta with a deterministic digest.
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
    /// Records that a previously admitted assertion is absent from a complete scope.
    ///
    /// Repeating an assertion ID replaces its reason. The capability is
    /// unavailable on [`GraphDeltaBuilder<NonAuthoritative>`].
    ///
    /// # Errors
    ///
    /// Returns a model error when `reason` violates the text contract.
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
    fn relationship_workspace_scope_must_match_both_endpoints() {
        let receipt = receipt();
        let team = Entity::canonical(
            TenantId::parse("tenant-a").unwrap(),
            EntityId::parse("group-workspace").unwrap(),
            EntityKind::Team,
            "team",
        )
        .unwrap()
        .with_property("application_workspace_id", "workspace-a")
        .unwrap();
        let repository = Entity::canonical(
            TenantId::parse("tenant-a").unwrap(),
            EntityId::parse("repository-workspace").unwrap(),
            EntityKind::Repository,
            "repository",
        )
        .unwrap()
        .with_property("application_workspace_id", "workspace-a")
        .unwrap();
        let assertion = RelationshipAssertion::new(
            &team,
            RelationKind::Owns,
            &repository,
            provenance(receipt.receipt()),
            10,
        )
        .unwrap();
        assert_eq!(assertion.application_workspace_id(), "workspace-a");

        let other_workspace = repository
            .with_property("application_workspace_id", "workspace-b")
            .unwrap();
        assert_eq!(
            RelationshipAssertion::new(
                &team,
                RelationKind::Owns,
                &other_workspace,
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
