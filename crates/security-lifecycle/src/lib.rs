#![forbid(unsafe_code)]

//! Credential and certificate lifecycle authority.
//!
//! Provider adapters publish metadata-only observations. This crate owns
//! stable identity, expiry policy, bounded reads, action routing, and the
//! evidence rule for closing a finding.

use std::{collections::BTreeMap, error::Error, fmt};

use cerebro_organizational_model::{
    AssertionProvenance, CollectionReceipt, Entity, EntityId, EntityKind, GraphAssertion,
    GraphDelta, ObservationId, ObservationRef, RelationKind, RelationshipAssertion, TenantId,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

/// Event kind admitted for credential lifecycle observations.
pub const CREDENTIAL_EVENT_KIND: &str = "security.credential.lifecycle";
/// Event kind admitted for certificate lifecycle observations.
pub const CERTIFICATE_EVENT_KIND: &str = "security.certificate.lifecycle";
/// Versioned payload schema required by [`CREDENTIAL_EVENT_KIND`].
pub const CREDENTIAL_SCHEMA_REF: &str = "cerebro/security/credential-lifecycle/v1";
/// Versioned payload schema required by [`CERTIFICATE_EVENT_KIND`].
pub const CERTIFICATE_SCHEMA_REF: &str = "cerebro/security/certificate-lifecycle/v1";
/// Stable identifier for the built-in lifecycle expiry policy.
pub const EXPIRY_POLICY_ID: &str = "security.lifecycle.expiry";
/// Semantic version of the built-in lifecycle expiry policy.
pub const EXPIRY_POLICY_VERSION: &str = "1";
/// Default inclusive window in which active material is classified as expiring.
pub const DEFAULT_WARNING_WINDOW_DAYS: u32 = 30;
/// Page size used when a query does not specify a limit.
pub const DEFAULT_QUERY_LIMIT: usize = 100;
/// Largest page size accepted by scan and indexed query paths.
pub const MAX_QUERY_LIMIT: usize = 500;

// Cursors freeze evaluation time for at most one short navigation session. These
// limits bound both parsing allocation and keyset work before graph access.
const MAX_CURSOR_AGE: Duration = Duration::minutes(15);
const MAX_CURSOR_SUBJECT_URN_BYTES: usize = 2_048;
const MAX_PAGE_TOKEN_CHARS: usize = 4_608;
const MAX_QUERY_FILTER_VALUES: usize = 100;

/// Protobuf representation of a cross-surface resource reference.
///
/// `api_path` and `mcp_uri` remain on the v1 wire for compatibility, but lifecycle
/// authority is derived exclusively from canonical `kind`, `id`, revision, and state.
#[derive(Clone, PartialEq, Message)]
struct WireResourceRef {
    #[prost(string, tag = "1")]
    kind: String,
    #[prost(string, tag = "2")]
    id: String,
    #[prost(string, tag = "3")]
    revision: String,
    #[prost(string, tag = "4")]
    api_path: String,
    #[prost(string, tag = "5")]
    mcp_uri: String,
    #[prost(string, tag = "6")]
    state: String,
}

/// Credential-free protobuf payload admitted from a lifecycle event envelope.
///
/// The payload carries identifiers and metadata only. Secret-bearing attribute
/// names and recognizable private-key material are rejected after decoding.
#[derive(Clone, PartialEq, Message)]
struct WireObservation {
    #[prost(message, optional, tag = "1")]
    subject_ref: Option<WireResourceRef>,
    #[prost(enumeration = "WireSubjectKind", tag = "2")]
    subject_kind: i32,
    #[prost(string, tag = "3")]
    provider: String,
    #[prost(string, tag = "4")]
    authority_id: String,
    #[prost(string, tag = "5")]
    stable_locator: String,
    #[prost(string, tag = "6")]
    display_name: String,
    #[prost(enumeration = "WireLifecycleState", tag = "7")]
    state: i32,
    #[prost(message, optional, tag = "8")]
    observed_at: Option<prost_types::Timestamp>,
    #[prost(message, optional, tag = "9")]
    issued_at: Option<prost_types::Timestamp>,
    #[prost(message, optional, tag = "10")]
    expires_at: Option<prost_types::Timestamp>,
    #[prost(message, optional, tag = "11")]
    rotated_at: Option<prost_types::Timestamp>,
    #[prost(message, optional, tag = "12")]
    revoked_at: Option<prost_types::Timestamp>,
    #[prost(string, tag = "13")]
    owner_urn: String,
    #[prost(message, repeated, tag = "14")]
    scope_refs: Vec<WireResourceRef>,
    #[prost(message, repeated, tag = "15")]
    evidence_claim_refs: Vec<WireResourceRef>,
    #[prost(map = "string, string", tag = "16")]
    attributes: std::collections::HashMap<String, String>,
}

/// Closed protobuf discriminator for the resource family being observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum WireSubjectKind {
    /// Missing or unsupported discriminator; always rejected at admission.
    Unspecified = 0,
    /// Credential material occupying a stable logical slot.
    Credential = 1,
    /// Certificate material occupying a stable logical slot.
    Certificate = 2,
}

/// Closed protobuf representation of provider lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum WireLifecycleState {
    /// Missing state; always rejected at admission.
    Unspecified = 0,
    /// Material is active and may or may not declare an expiry.
    Active = 1,
    /// Provider explicitly reports that material is nearing expiry.
    Expiring = 2,
    /// Provider explicitly reports expired material.
    Expired = 3,
    /// A newer material revision replaced this one.
    Rotated = 4,
    /// Provider revoked the material.
    Revoked = 5,
    /// Material is inactive without a stronger terminal state.
    Inactive = 6,
    /// Provider cannot establish the lifecycle state.
    Unknown = 7,
}

// Only metadata with an explicit product use is admitted. The secondary fragment
// denylist keeps future allowlist additions from accidentally admitting common
// secret-bearing names.
const ALLOWED_ATTRIBUTES: &[&str] = &[
    "algorithm",
    "environment",
    "issuer",
    "location",
    "managed",
    "policy_id",
    "purpose",
    "rotation_policy",
    "serial_number",
    "source_collection_id",
];
const FORBIDDEN_ATTRIBUTE_FRAGMENTS: &[&str] = &[
    "secret",
    "access_token",
    "api_key",
    "authorization",
    "bearer_token",
    "private_key",
    "private-key",
    "password",
    "passphrase",
    "token_value",
    "credential_value",
    "certificate_key",
    "pem",
    "pkcs",
];

/// Typed rejection at the lifecycle admission, policy, projection, or query boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    /// A required field or invariant identified by a stable field label is invalid.
    Invalid(&'static str),
    /// A bounded error whose message needs request-specific context.
    InvalidValue(String),
    /// Metadata was rejected because its name or value could contain secret material.
    SecretMaterial(String),
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(field) => write!(formatter, "{field} is invalid"),
            Self::InvalidValue(message) | Self::SecretMaterial(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl Error for LifecycleError {}

/// Lifecycle resource family used for contracts, identity, policy, and actions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// A credential such as an API credential or signing key slot.
    Credential,
    /// A certificate slot whose material can be renewed.
    Certificate,
}

impl SubjectKind {
    /// Returns the exact event kind and schema reference for this family.
    pub fn event_contract(self) -> (&'static str, &'static str) {
        match self {
            Self::Credential => (CREDENTIAL_EVENT_KIND, CREDENTIAL_SCHEMA_REF),
            Self::Certificate => (CERTIFICATE_EVENT_KIND, CERTIFICATE_SCHEMA_REF),
        }
    }

    /// Returns the canonical lowercase identity segment for this family.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Certificate => "certificate",
        }
    }
}

/// Provider-observed lifecycle state before policy evaluation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    /// Material is active; expiry policy derives compliance from `expires_at`.
    Active,
    /// Provider explicitly marks the material as nearing expiry.
    Expiring,
    /// Provider explicitly marks the material as expired.
    Expired,
    /// Material has been replaced by a newer revision.
    Rotated,
    /// Material has been revoked.
    Revoked,
    /// Material is no longer active.
    Inactive,
    /// Provider could not determine a state.
    Unknown,
}

/// Canonical reference to a tenant-scoped product object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRef {
    /// Provider-neutral object kind.
    pub kind: String,
    /// Canonical tenant-scoped URN.
    pub id: String,
    /// Optional material or object revision; never part of stable slot identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// Optional state of the referenced object at observation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Validated metadata-only observation of one credential or certificate slot.
///
/// `authority_id` and `stable_locator` determine the stable subject URN. Material
/// rotation changes `subject_ref.revision`, not `subject_ref.id`, so findings and
/// action routes remain attached to the logical slot across replacements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Stable subject slot and current material revision.
    pub subject_ref: ResourceRef,
    /// Credential or certificate semantics for this subject.
    pub subject_kind: SubjectKind,
    /// Provider that reported the observation.
    pub provider: String,
    /// Stable provider account, issuer, or administrative authority.
    pub authority_id: String,
    /// Stable slot locator within the authority.
    pub stable_locator: String,
    /// Human-readable subject name; never used for identity.
    pub display_name: String,
    /// Provider-observed lifecycle state.
    pub state: LifecycleState,
    /// RFC 3339 time correlated exactly with the event envelope and collection receipt.
    pub observed_at: String,
    /// Optional RFC 3339 issue time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    /// Optional RFC 3339 expiry time used by the built-in policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Optional RFC 3339 rotation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<String>,
    /// Optional RFC 3339 revocation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    /// Optional tenant-scoped accountable owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_urn: Option<String>,
    /// Tenant-scoped resources within the material's declared scope.
    #[serde(default)]
    pub scope_refs: Vec<ResourceRef>,
    /// Tenant-scoped claims that support this observation.
    #[serde(default)]
    pub evidence_claim_refs: Vec<ResourceRef>,
    /// Explicitly allowlisted, secret-free provider metadata.
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

/// Minimal graph resource representation consumed by lifecycle reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedResource {
    /// Stable graph key used when a legacy projection lacks `resource_urn`.
    pub agent_key: String,
    /// Human-readable graph label.
    pub label: String,
    /// String-valued projection properties, including encoded repeated metadata.
    pub properties: BTreeMap<String, String>,
}

impl Observation {
    /// Validates stable identity, times, tenant isolation, and the metadata allowlist.
    ///
    /// Validation reconstructs the canonical subject URN from authenticated tenant
    /// context rather than trusting the payload identity. Attribute names must be on
    /// the allowlist and values are screened for recognizable private-key envelopes.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::Invalid`] for identity or time failures and
    /// [`LifecycleError::SecretMaterial`] for prohibited metadata.
    pub fn validate(&self, tenant_id: &TenantId) -> Result<(), LifecycleError> {
        for (field, value) in [
            ("provider", self.provider.as_str()),
            ("authority_id", self.authority_id.as_str()),
            ("stable_locator", self.stable_locator.as_str()),
            ("display_name", self.display_name.as_str()),
            ("subject_ref.id", self.subject_ref.id.as_str()),
            (
                "subject_ref.revision",
                self.subject_ref.revision.as_deref().unwrap_or_default(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(LifecycleError::Invalid(field));
            }
        }
        let expected = canonical_resource_urn(
            tenant_id.as_str(),
            self.subject_kind,
            &self.authority_id,
            &self.stable_locator,
        )?;
        if self.subject_ref.id != expected || self.subject_ref.kind != self.subject_kind.as_str() {
            return Err(LifecycleError::Invalid("subject_ref"));
        }
        parse_time(&self.observed_at, "observed_at")?;
        for (field, value) in [
            ("issued_at", self.issued_at.as_deref()),
            ("expires_at", self.expires_at.as_deref()),
            ("rotated_at", self.rotated_at.as_deref()),
            ("revoked_at", self.revoked_at.as_deref()),
        ] {
            if let Some(value) = value {
                parse_time(value, field)?;
            }
        }
        // Normalize names only for policy checks. The original key and value are
        // retained for projection after they pass the credential-free boundary.
        for (key, value) in &self.attributes {
            let normalized = key.trim().to_ascii_lowercase();
            if !ALLOWED_ATTRIBUTES.contains(&normalized.as_str())
                || FORBIDDEN_ATTRIBUTE_FRAGMENTS
                    .iter()
                    .any(|fragment| normalized.contains(fragment))
            {
                return Err(LifecycleError::SecretMaterial(format!(
                    "attribute {key:?} is not permitted"
                )));
            }
            let upper = value.trim().to_ascii_uppercase();
            if upper.contains("-----BEGIN ") || upper.contains("PRIVATE KEY-----") {
                return Err(LifecycleError::SecretMaterial(format!(
                    "attribute {key:?} contains key material"
                )));
            }
        }
        for reference in self
            .scope_refs
            .iter()
            .chain(self.evidence_claim_refs.iter())
        {
            require_tenant_urn(tenant_id.as_str(), &reference.id)?;
        }
        if let Some(owner_urn) = self.owner_urn.as_deref() {
            require_tenant_urn(tenant_id.as_str(), owner_urn)?;
        }
        Ok(())
    }

    /// Reconstructs a lifecycle observation from graph projection properties.
    ///
    /// Returns `Ok(None)` for unrelated or incomplete resources so broad scans can
    /// skip them. Once an entity declares both lifecycle kind and state, malformed
    /// state or encoded JSON is an error rather than a silent omission.
    pub fn from_graph(entity: ProjectedResource) -> Result<Option<Self>, LifecycleError> {
        let properties = entity.properties;
        let Some(subject_kind) = properties
            .get("subject_kind")
            .and_then(|value| parse_subject_kind(value))
        else {
            return Ok(None);
        };
        let Some(state_value) = properties.get("lifecycle_state") else {
            return Ok(None);
        };
        let Some(state) = parse_state(state_value) else {
            return Err(LifecycleError::Invalid("lifecycle_state"));
        };
        let required = |key: &'static str| {
            properties
                .get(key)
                .cloned()
                .filter(|value| !value.trim().is_empty())
        };
        let (Some(provider), Some(authority_id), Some(stable_locator), Some(observed_at)) = (
            required("provider"),
            required("authority_id"),
            required("stable_locator"),
            required("observed_at"),
        ) else {
            return Ok(None);
        };
        let subject_id = properties
            .get("resource_urn")
            .cloned()
            .unwrap_or(entity.agent_key);
        let scope_refs = graph_json_property(&properties, "scope_refs")?;
        let evidence_claim_refs = graph_json_property(&properties, "evidence_claim_refs")?;
        let attributes = graph_json_property(&properties, "attributes")?;
        Ok(Some(Self {
            subject_ref: ResourceRef {
                kind: subject_kind.as_str().to_owned(),
                id: subject_id,
                revision: properties.get("material_revision").cloned(),
                state: Some(state_name(state).to_owned()),
            },
            subject_kind,
            provider,
            authority_id,
            stable_locator,
            display_name: entity.label,
            state,
            observed_at,
            issued_at: properties.get("issued_at").cloned(),
            expires_at: properties.get("expires_at").cloned(),
            rotated_at: properties.get("rotated_at").cloned(),
            revoked_at: properties.get("revoked_at").cloned(),
            owner_urn: properties.get("owner_urn").cloned(),
            scope_refs,
            evidence_claim_refs,
            attributes,
        }))
    }
}

/// Decodes and validates one protobuf lifecycle event payload.
///
/// The payload observation time must equal the authenticated envelope time at
/// millisecond precision. This binds projection to the admitted event and prevents
/// provider-controlled timestamps from being substituted after admission.
///
/// # Errors
///
/// Returns a typed lifecycle error for malformed protobuf, unsupported enum values,
/// invalid timestamps, envelope-time mismatch, tenant mismatch, or secret metadata.
pub fn decode_protobuf_observation(
    payload: &[u8],
    tenant_id: &TenantId,
    occurred_at_unix_ms: i64,
) -> Result<Observation, LifecycleError> {
    let wire = WireObservation::decode(payload).map_err(|error| {
        LifecycleError::InvalidValue(format!("invalid lifecycle payload: {error}"))
    })?;
    let subject_kind = match WireSubjectKind::try_from(wire.subject_kind).ok() {
        Some(WireSubjectKind::Credential) => SubjectKind::Credential,
        Some(WireSubjectKind::Certificate) => SubjectKind::Certificate,
        _ => return Err(LifecycleError::Invalid("subject_kind")),
    };
    let state = match WireLifecycleState::try_from(wire.state).ok() {
        Some(WireLifecycleState::Active) => LifecycleState::Active,
        Some(WireLifecycleState::Expiring) => LifecycleState::Expiring,
        Some(WireLifecycleState::Expired) => LifecycleState::Expired,
        Some(WireLifecycleState::Rotated) => LifecycleState::Rotated,
        Some(WireLifecycleState::Revoked) => LifecycleState::Revoked,
        Some(WireLifecycleState::Inactive) => LifecycleState::Inactive,
        Some(WireLifecycleState::Unknown) => LifecycleState::Unknown,
        _ => return Err(LifecycleError::Invalid("state")),
    };
    let observed_at = wire
        .observed_at
        .as_ref()
        .ok_or(LifecycleError::Invalid("observed_at"))
        .and_then(|value| wire_timestamp(value, "observed_at"))?;
    if timestamp_millis_from_rfc3339(&observed_at)? != occurred_at_unix_ms {
        return Err(LifecycleError::Invalid("EventEnvelope.occurred_at"));
    }
    let observation = Observation {
        subject_ref: resource_ref(
            wire.subject_ref
                .ok_or(LifecycleError::Invalid("subject_ref"))?,
        ),
        subject_kind,
        provider: wire.provider,
        authority_id: wire.authority_id,
        stable_locator: wire.stable_locator,
        display_name: wire.display_name,
        state,
        observed_at,
        issued_at: wire
            .issued_at
            .as_ref()
            .map(|value| wire_timestamp(value, "issued_at"))
            .transpose()?,
        expires_at: wire
            .expires_at
            .as_ref()
            .map(|value| wire_timestamp(value, "expires_at"))
            .transpose()?,
        rotated_at: wire
            .rotated_at
            .as_ref()
            .map(|value| wire_timestamp(value, "rotated_at"))
            .transpose()?,
        revoked_at: wire
            .revoked_at
            .as_ref()
            .map(|value| wire_timestamp(value, "revoked_at"))
            .transpose()?,
        owner_urn: (!wire.owner_urn.trim().is_empty()).then_some(wire.owner_urn),
        scope_refs: wire.scope_refs.into_iter().map(resource_ref).collect(),
        evidence_claim_refs: wire
            .evidence_claim_refs
            .into_iter()
            .map(resource_ref)
            .collect(),
        attributes: wire.attributes.into_iter().collect(),
    };
    observation.validate(tenant_id)?;
    Ok(observation)
}

/// Projects a validated observation and any open expiry finding into one graph delta.
///
/// The collection receipt supplies authenticated tenant and runtime authority. Its
/// observation time must equal the payload time. The resource entity is always
/// emitted; a finding and `affects` assertion are emitted only when policy state is
/// `expiring` or `expired`.
///
/// # Errors
///
/// Returns an error when observation authority, collection time, graph identifiers,
/// properties, provenance, or relationship construction is invalid.
pub fn project_observation(
    receipt: CollectionReceipt,
    observation_id: ObservationId,
    observation: &Observation,
) -> Result<GraphDelta, LifecycleError> {
    observation.validate(receipt.tenant_id())?;
    let observed_at_unix_ms = timestamp_millis_from_rfc3339(&observation.observed_at)?;
    if observed_at_unix_ms != receipt.observed_at_unix_ms() {
        return Err(LifecycleError::Invalid("collection observed time"));
    }
    // Graph EntityId has a bounded syntax, so it is derived from the canonical URN.
    // The full URN remains a property and is the product-facing stable identity.
    let subject_id = stable_entity_id("security-lifecycle-resource", &observation.subject_ref.id)?;
    let mut subject = Entity::canonical(
        receipt.tenant_id().clone(),
        subject_id,
        EntityKind::Resource,
        observation.display_name.clone(),
    )
    .map_err(model_error)?;
    for (key, value) in projection_properties(observation)? {
        subject = subject.with_property(key, value).map_err(model_error)?;
    }
    subject = subject
        .with_property(
            "source_runtime_id",
            receipt.source_runtime_id().as_str().to_owned(),
        )
        .map_err(model_error)?;
    if let Some(source_collection_id) = observation.attributes.get("source_collection_id") {
        subject = subject
            .with_property("source_collection_id", source_collection_id.clone())
            .map_err(model_error)?;
    }
    let observation_ref =
        ObservationRef::new(&receipt, observation_id, observation.subject_ref.id.clone())
            .map_err(model_error)?;
    let provenance = AssertionProvenance::direct(
        vec![observation_ref],
        "cerebro-security-lifecycle",
        env!("CARGO_PKG_VERSION"),
    )
    .map_err(model_error)?;
    let tenant_id = receipt.tenant_id().clone();
    let source_runtime_id = receipt.source_runtime_id().as_str().to_owned();
    let mut builder = receipt.begin_delta();
    builder.add_entity(subject.clone()).map_err(model_error)?;

    let evaluation = evaluate(
        observation,
        &observation.observed_at,
        DEFAULT_WARNING_WINDOW_DAYS,
    )?;
    if evaluation.has_finding() {
        // Finding identity is derived from the stable slot URN rather than material
        // revision, keeping one durable finding lane across credential rotation.
        let finding_urn = canonical_finding_urn(tenant_id.as_str(), &observation.subject_ref.id)?;
        let finding_id = stable_entity_id("security-lifecycle-finding", &finding_urn)?;
        let mut finding = Entity::canonical(
            tenant_id,
            finding_id,
            EntityKind::Finding,
            format!("{} expires", observation.display_name),
        )
        .map_err(model_error)?
        .with_property("resource_urn", finding_urn)
        .and_then(|entity| {
            entity.with_property(
                "finding_kind",
                format!("{}_expiry", observation.subject_kind.as_str()),
            )
        })
        .and_then(|entity| entity.with_property("status", "open"))
        .and_then(|entity| entity.with_property("policy_id", EXPIRY_POLICY_ID))
        .and_then(|entity| entity.with_property("subject_urn", observation.subject_ref.id.clone()))
        .and_then(|entity| entity.with_property("source_runtime_id", source_runtime_id))
        .map_err(model_error)?;
        if let Some(source_collection_id) = observation.attributes.get("source_collection_id") {
            finding = finding
                .with_property("source_collection_id", source_collection_id.clone())
                .map_err(model_error)?;
        }
        let assertion = RelationshipAssertion::new(
            &finding,
            RelationKind::Affects,
            &subject,
            provenance,
            observed_at_unix_ms,
        )
        .map_err(model_error)?;
        builder.add_entity(finding).map_err(model_error)?;
        builder
            .add_assertion(GraphAssertion::Relationship(assertion))
            .map_err(model_error)?;
    }
    Ok(builder.build())
}

/// Serializes all observation fields required for a lossless graph read.
///
/// Repeated and map values are encoded as JSON strings because the organizational
/// graph property contract is scalar. Empty optional collections are omitted.
fn projection_properties(
    observation: &Observation,
) -> Result<BTreeMap<String, String>, LifecycleError> {
    let mut properties = BTreeMap::from([
        (
            "resource_urn".to_owned(),
            observation.subject_ref.id.clone(),
        ),
        (
            "material_revision".to_owned(),
            observation.subject_ref.revision.clone().unwrap_or_default(),
        ),
        (
            "subject_kind".to_owned(),
            observation.subject_kind.as_str().to_owned(),
        ),
        (
            "lifecycle_state".to_owned(),
            state_name(observation.state).to_owned(),
        ),
        ("provider".to_owned(), observation.provider.clone()),
        ("authority_id".to_owned(), observation.authority_id.clone()),
        (
            "stable_locator".to_owned(),
            observation.stable_locator.clone(),
        ),
        ("observed_at".to_owned(), observation.observed_at.clone()),
    ]);
    for (key, value) in [
        ("issued_at", observation.issued_at.as_ref()),
        ("expires_at", observation.expires_at.as_ref()),
        ("rotated_at", observation.rotated_at.as_ref()),
        ("revoked_at", observation.revoked_at.as_ref()),
        ("owner_urn", observation.owner_urn.as_ref()),
    ] {
        if let Some(value) = value {
            properties.insert(key.to_owned(), value.clone());
        }
    }
    if !observation.scope_refs.is_empty() {
        insert_graph_json_property(&mut properties, "scope_refs", &observation.scope_refs)?;
    }
    if !observation.evidence_claim_refs.is_empty() {
        insert_graph_json_property(
            &mut properties,
            "evidence_claim_refs",
            &observation.evidence_claim_refs,
        )?;
    }
    if !observation.attributes.is_empty() {
        insert_graph_json_property(&mut properties, "attributes", &observation.attributes)?;
    }
    Ok(properties)
}

/// Encodes one structured value into a scalar graph property.
fn insert_graph_json_property(
    properties: &mut BTreeMap<String, String>,
    key: &'static str,
    value: &impl Serialize,
) -> Result<(), LifecycleError> {
    let encoded = serde_json::to_string(value)
        .map_err(|error| LifecycleError::InvalidValue(format!("invalid {key}: {error}")))?;
    properties.insert(key.to_owned(), encoded);
    Ok(())
}

/// Decodes an optional structured graph property, defaulting only when absent.
///
/// Present malformed JSON fails closed so a corrupted lifecycle projection cannot
/// be mistaken for an intentionally empty collection.
fn graph_json_property<T>(
    properties: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<T, LifecycleError>
where
    T: for<'de> Deserialize<'de> + Default,
{
    properties
        .get(key)
        .map(|value| {
            serde_json::from_str(value)
                .map_err(|error| LifecycleError::InvalidValue(format!("invalid {key}: {error}")))
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

/// Deterministic result of applying the built-in expiry policy to one observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyEvaluation {
    /// Stable policy identifier.
    pub policy_id: &'static str,
    /// Policy semantics version.
    pub policy_version: &'static str,
    /// Subject evaluated by the policy.
    pub subject_ref: ResourceRef,
    /// `compliant`, `expiring`, `expired`, or `unknown`.
    pub state: &'static str,
    /// Inclusive warning window used for this evaluation.
    pub warning_window_days: u32,
    /// Signed duration from evaluation time to expiry, when expiry is known.
    pub seconds_until_expiry: Option<i64>,
    /// RFC 3339 time at which policy state was calculated.
    pub evaluated_at: String,
    /// Claims carried forward as supporting evidence.
    pub evidence_claim_refs: Vec<ResourceRef>,
}

impl PolicyEvaluation {
    /// Returns whether this policy state requires an open lifecycle finding.
    pub fn has_finding(&self) -> bool {
        matches!(self.state, "expiring" | "expired")
    }
}

/// Applies lifecycle-state precedence and the expiry window at a caller-supplied time.
///
/// Explicit `expired` and `expiring` provider states win. Rotated, revoked, and
/// inactive material is compliant regardless of historical expiry. Active material
/// is derived from `expires_at`; an active observation without expiry is unknown.
///
/// # Errors
///
/// Returns an error when the evaluation or expiry time is not RFC 3339.
pub fn evaluate(
    observation: &Observation,
    evaluated_at: &str,
    warning_window_days: u32,
) -> Result<PolicyEvaluation, LifecycleError> {
    let evaluated = parse_time(evaluated_at, "evaluated_at")?;
    let expiry = observation
        .expires_at
        .as_deref()
        .map(|value| parse_time(value, "expires_at"))
        .transpose()?;
    let seconds_until_expiry = expiry.map(|value| (value - evaluated).whole_seconds());
    let state = match observation.state {
        LifecycleState::Expired => "expired",
        LifecycleState::Expiring => "expiring",
        LifecycleState::Rotated | LifecycleState::Revoked | LifecycleState::Inactive => "compliant",
        LifecycleState::Active => match seconds_until_expiry {
            Some(seconds) if seconds <= 0 => "expired",
            Some(seconds)
                if seconds <= i64::from(warning_window_days).saturating_mul(24 * 60 * 60) =>
            {
                "expiring"
            }
            Some(_) => "compliant",
            None => "unknown",
        },
        LifecycleState::Unknown => "unknown",
    };
    Ok(PolicyEvaluation {
        policy_id: EXPIRY_POLICY_ID,
        policy_version: EXPIRY_POLICY_VERSION,
        subject_ref: observation.subject_ref.clone(),
        state,
        warning_window_days,
        seconds_until_expiry,
        evaluated_at: evaluated_at.to_owned(),
        evidence_claim_refs: observation.evidence_claim_refs.clone(),
    })
}

/// Product binding between an open finding, its subject, and supporting evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FindingBinding {
    /// Stable tenant-scoped finding.
    pub finding_ref: ResourceRef,
    /// Credential or certificate slot affected by the finding.
    pub subject_ref: ResourceRef,
    /// Family-specific finding kind such as `credential_expiry`.
    pub finding_kind: String,
    /// Current finding status; records produced here are open.
    pub status: String,
    /// Evidence claims copied from the observation.
    pub evidence_claim_refs: Vec<ResourceRef>,
}

/// Opaque references required to route an approved lifecycle remediation.
///
/// This record describes intent and correlation only. It does not contain provider
/// credentials, private routes, or proof that an action was authorized or executed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionRoute {
    /// Finding that motivates the action.
    pub finding_ref: ResourceRef,
    /// Stable subject slot to rotate or renew.
    pub target_ref: ResourceRef,
    /// `rotate_credential` or `renew_certificate`.
    pub action_type: String,
    /// Whether dispatch must wait for an approval decision.
    pub approval_required: bool,
    /// Stable opaque action-intent reference.
    pub action_intent_ref: ResourceRef,
    /// Stable opaque dispatch reference.
    pub dispatch_ref: ResourceRef,
    /// Stable opaque verification reference.
    pub verification_ref: ResourceRef,
}

/// Builds deterministic action correlation references for an open finding.
///
/// Subject and finding references must belong to the authenticated tenant. Opaque
/// child references share the finding suffix so downstream records can correlate
/// without embedding provider-specific execution details.
pub fn action_route(
    tenant_id: &TenantId,
    finding_ref: ResourceRef,
    observation: &Observation,
    approval_required: bool,
) -> Result<ActionRoute, LifecycleError> {
    require_tenant_urn(tenant_id.as_str(), &finding_ref.id)?;
    require_tenant_urn(tenant_id.as_str(), &observation.subject_ref.id)?;
    let finding_id = finding_ref
        .id
        .rsplit(':')
        .next()
        .ok_or(LifecycleError::Invalid("finding_ref"))?
        .to_owned();
    let opaque = |kind: &str| ResourceRef {
        kind: kind.to_owned(),
        id: format!(
            "urn:cerebro:{}:{}:{}",
            encode_segment(tenant_id.as_str()),
            kind,
            finding_id
        ),
        revision: None,
        state: None,
    };
    Ok(ActionRoute {
        finding_ref,
        target_ref: observation.subject_ref.clone(),
        action_type: match observation.subject_kind {
            SubjectKind::Credential => "rotate_credential",
            SubjectKind::Certificate => "renew_certificate",
        }
        .to_owned(),
        approval_required,
        action_intent_ref: opaque("action_intent"),
        dispatch_ref: opaque("dispatch"),
        verification_ref: opaque("verification"),
    })
}

/// Authority that a post-remediation observation must satisfy before closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationExpectation {
    /// Authenticated tenant for every bound reference.
    pub tenant_id: TenantId,
    /// Finding awaiting closure evidence.
    pub finding_ref: ResourceRef,
    /// Recorded provider remediation outcome; success alone is insufficient.
    pub remediation_outcome_ref: ResourceRef,
    /// Stable subject slot that must be recollected.
    pub subject_ref: ResourceRef,
    /// Exact source runtime that must produce the fresh observation.
    pub source_runtime_ref: ResourceRef,
    /// RFC 3339 dispatch time; qualifying evidence must be strictly later.
    pub dispatched_at: String,
}

/// Evidence binding that either verifies closure or records why verification remains pending.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerificationBinding {
    /// Finding evaluated for closure.
    pub finding_ref: ResourceRef,
    /// Remediation outcome correlated with this verification.
    pub remediation_outcome_ref: ResourceRef,
    /// Fresh observation event considered by the verifier.
    pub observation_event_ref: ResourceRef,
    /// Runtime that produced the observation.
    pub source_runtime_ref: ResourceRef,
    /// `verified_closed` or `verification_pending`.
    pub result: &'static str,
    /// Whether recollection covered the declared source scope.
    pub source_complete: bool,
    /// Whether provider or runtime bounds truncated recollection.
    pub source_truncated: bool,
    /// RFC 3339 observation time used for freshness.
    pub observed_at: String,
    /// Claims supporting the observed lifecycle state.
    pub evidence_claim_refs: Vec<ResourceRef>,
}

/// Binds post-action recollection to a finding and decides whether it can close.
///
/// Closure requires all of the following: matching tenant-scoped subject and source
/// runtime, observation strictly after dispatch, complete and untruncated collection,
/// and a compliant policy result. A provider success response never substitutes for
/// fresh observed state.
///
/// # Errors
///
/// Returns an error for invalid observation authority, foreign references, subject or
/// runtime mismatch, invalid times, or policy-evaluation failure.
pub fn bind_verification(
    observation: &Observation,
    observation_event_ref: ResourceRef,
    observed_source_runtime_ref: ResourceRef,
    expectation: &VerificationExpectation,
    source_complete: bool,
    source_truncated: bool,
    warning_window_days: u32,
) -> Result<VerificationBinding, LifecycleError> {
    observation.validate(&expectation.tenant_id)?;
    for reference in [
        &expectation.finding_ref,
        &expectation.remediation_outcome_ref,
        &expectation.subject_ref,
        &expectation.source_runtime_ref,
        &observation_event_ref,
        &observed_source_runtime_ref,
    ] {
        require_tenant_urn(expectation.tenant_id.as_str(), &reference.id)?;
    }
    if observation.subject_ref.id != expectation.subject_ref.id
        || observed_source_runtime_ref.id != expectation.source_runtime_ref.id
    {
        return Err(LifecycleError::Invalid("verification subject"));
    }
    let observed_at = parse_time(&observation.observed_at, "observed_at")?;
    let dispatched_at = parse_time(&expectation.dispatched_at, "dispatched_at")?;
    let fresh = observed_at > dispatched_at;
    let compliant =
        evaluate(observation, &observation.observed_at, warning_window_days)?.state == "compliant";
    let result = if fresh && source_complete && !source_truncated && compliant {
        "verified_closed"
    } else {
        "verification_pending"
    };
    Ok(VerificationBinding {
        finding_ref: expectation.finding_ref.clone(),
        remediation_outcome_ref: expectation.remediation_outcome_ref.clone(),
        observation_event_ref,
        source_runtime_ref: observed_source_runtime_ref,
        result,
        source_complete,
        source_truncated,
        observed_at: observation.observed_at.clone(),
        evidence_claim_refs: observation.evidence_claim_refs.clone(),
    })
}

/// Bounded filters and keyset cursor for lifecycle reads.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct LifecycleQuery {
    /// Accepted resource families; empty means both families.
    #[serde(default)]
    pub subject_kinds: Vec<SubjectKind>,
    /// Accepted provider-observed states; empty means every state.
    #[serde(default)]
    pub states: Vec<LifecycleState>,
    /// Accepted tenant-scoped owner URNs; empty means every owner.
    #[serde(default)]
    pub owner_urns: Vec<String>,
    /// Exclusive RFC 3339 expiry cutoff; missing or later expiry does not match.
    #[serde(default)]
    pub expires_before: Option<String>,
    /// When true, omit subjects whose policy evaluation has no finding.
    #[serde(default)]
    pub findings_only: bool,
    /// Requested page size from 1 through [`MAX_QUERY_LIMIT`].
    #[serde(default)]
    pub limit: Option<usize>,
    /// Opaque v2 keyset token returned by an earlier equivalent query.
    #[serde(default)]
    pub page_token: Option<String>,
    /// Exact stable subject slot to resolve, independent of material revision.
    #[serde(default)]
    pub subject_locator: Option<SubjectLocator>,
}

/// Provider-neutral components that resolve one stable lifecycle subject URN.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SubjectLocator {
    /// Credential or certificate namespace.
    pub subject_kind: SubjectKind,
    /// Provider authority containing the slot.
    pub authority_id: String,
    /// Stable slot within the authority.
    pub stable_locator: String,
}

/// Product read model for one lifecycle subject at a fixed evaluation time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LifecycleRecord {
    /// Current metadata-only observation reconstructed from the graph.
    pub observation: Observation,
    /// Policy results calculated for this read.
    pub policy_evaluations: Vec<PolicyEvaluation>,
    /// Open findings derived from those policy results.
    pub findings: Vec<FindingBinding>,
    /// Opaque action routes available for the findings.
    pub action_routes: Vec<ActionRoute>,
    /// Frozen query evaluation time, not the graph write time.
    pub projected_at: String,
    /// Source runtime recorded on the graph projection.
    pub source_runtime_id: String,
    /// Optional provider/runtime collection correlation identifier.
    pub source_collection_id: String,
}

/// One lifecycle query page with navigation, coverage, freshness, and aggregates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryResult {
    /// Stable-subject-ordered records for this page.
    pub records: Vec<LifecycleRecord>,
    /// Forward keyset cursor when a later page exists and the graph stayed stable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    /// Backward keyset cursor when an earlier page exists and the graph stayed stable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_page_token: Option<String>,
    /// Whether pagination or incomplete source coverage omits matching records.
    pub truncated: bool,
    /// Frozen RFC 3339 policy-evaluation time shared by every page in the cursor chain.
    pub as_of: String,
    /// Counts for the complete filtered population when coverage permits.
    pub aggregates: LifecycleAggregates,
    /// Coverage, freshness, and page-local truncation evidence.
    pub metadata: QueryMetadata,
}

/// Count of matching records for one subject family.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SubjectKindCount {
    /// Counted family.
    pub subject_kind: SubjectKind,
    /// Saturating count in the filtered population.
    pub count: u64,
}

/// Count of matching records for one observed lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StateCount {
    /// Counted provider-observed state.
    pub state: LifecycleState,
    /// Saturating count in the filtered population.
    pub count: u64,
}

/// Closed policy-state vocabulary used by aggregates.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    /// No expiry finding is required.
    Compliant,
    /// Expiry falls within the warning window.
    Expiring,
    /// Expiry has passed or was explicitly reported.
    Expired,
    /// Available evidence cannot determine compliance.
    Unknown,
}

/// Count of matching records for one derived policy state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyStateCount {
    /// Counted derived state.
    pub policy_state: PolicyState,
    /// Saturating count in the filtered population.
    pub count: u64,
}

/// Population-wide counts returned with a lifecycle page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LifecycleAggregates {
    /// Whether coverage proves every count is exact.
    pub counts_are_exact: bool,
    /// Total records matching filters before page slicing.
    pub matched_records: u64,
    /// Matching records whose policy evaluation has a finding.
    pub matched_findings: u64,
    /// Counts for both subject families, including zero entries.
    pub subject_kind_counts: Vec<SubjectKindCount>,
    /// Counts for every observed lifecycle state, including zero entries.
    pub state_counts: Vec<StateCount>,
    /// Counts for every derived policy state, including zero entries.
    pub policy_state_counts: Vec<PolicyStateCount>,
}

/// Reason a query does or does not cover its complete declared population.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageReason {
    /// The source covered the full population at one stable graph revision.
    Complete,
    /// A scan bound stopped before the full source population was read.
    ScanLimit,
    /// The graph revision changed while the query was being served.
    GraphChanged,
}

/// Evidence describing population coverage for a query result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryCoverage {
    /// Whether the result covers the complete declared source population.
    pub complete: bool,
    /// Whether a source bound or graph change truncated population coverage.
    pub truncated: bool,
    /// Generic graph entities inspected by an in-memory scan; zero for indexed reads.
    pub scanned_entities: u64,
    /// Lifecycle entities found before user filters.
    pub lifecycle_entities: u64,
    /// Graph revision against which the page was evaluated.
    pub graph_revision: u64,
    /// Machine-readable explanation of coverage state.
    pub reason: CoverageReason,
}

/// Observation-time range for the filtered lifecycle population.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryFreshness {
    /// Frozen policy-evaluation time.
    pub as_of: String,
    /// Oldest observation time among matched records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_observed_at: Option<String>,
    /// Newest observation time among matched records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_observed_at: Option<String>,
}

/// Operational evidence attached to every lifecycle query page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryMetadata {
    /// Population coverage and graph-revision evidence.
    pub coverage: QueryCoverage,
    /// Evaluation and observation-time evidence.
    pub freshness: QueryFreshness,
    /// Whether additional keyset pages exist, independent of source coverage.
    pub page_truncated: bool,
}

/// Source-scan evidence supplied by an in-memory graph reader.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuerySource {
    /// Number of generic graph entities inspected.
    pub scanned_entities: usize,
    /// Whether a scan limit stopped source enumeration.
    pub truncated: bool,
    /// Graph revision observed by the reader.
    pub graph_revision: u64,
    /// Whether the graph changed during enumeration.
    pub graph_changed: bool,
}

/// Direction of an indexed keyset query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeysetDirection {
    /// Read subjects lexically after the cursor.
    Forward,
    /// Read subjects lexically before the cursor.
    Backward,
}

/// Validated, normalized query contract passed to an indexed graph implementation.
///
/// Fields are private so an indexed adapter must obtain values through accessors and
/// cannot construct a query that bypasses cursor, tenant, filter, or time validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedLifecycleQuery {
    limit: usize,
    subject_kinds: Vec<SubjectKind>,
    states: Vec<LifecycleState>,
    owner_urns: Vec<String>,
    expires_before_unix_ms: Option<i64>,
    findings_only: bool,
    locator_urn: Option<String>,
    direction: KeysetDirection,
    cursor_subject_urn: Option<String>,
    graph_revision: u64,
    effective_as_of: String,
    effective_as_of_unix_ms: i64,
    warning_cutoff_unix_ms: i64,
    filter_digest: String,
}

impl PreparedLifecycleQuery {
    /// Returns the validated page size.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Returns sorted, deduplicated subject-family filters.
    pub fn subject_kinds(&self) -> &[SubjectKind] {
        &self.subject_kinds
    }

    /// Returns sorted, deduplicated observed-state filters.
    pub fn states(&self) -> &[LifecycleState] {
        &self.states
    }

    /// Returns sorted, deduplicated tenant-scoped owner filters.
    pub fn owner_urns(&self) -> &[String] {
        &self.owner_urns
    }

    /// Returns the optional exclusive expiry cutoff as Unix milliseconds.
    pub fn expires_before_unix_ms(&self) -> Option<i64> {
        self.expires_before_unix_ms
    }

    /// Returns whether only records with expiry findings should be selected.
    pub fn findings_only(&self) -> bool {
        self.findings_only
    }

    /// Returns the optional canonical subject URN resolved from [`SubjectLocator`].
    pub fn locator_urn(&self) -> Option<&str> {
        self.locator_urn.as_deref()
    }

    /// Returns the keyset direction selected by the page token.
    pub fn direction(&self) -> KeysetDirection {
        self.direction
    }

    /// Returns the exclusive keyset boundary, when continuing a page chain.
    pub fn cursor_subject_urn(&self) -> Option<&str> {
        self.cursor_subject_urn.as_deref()
    }

    /// Returns the graph revision to which this query is bound.
    pub fn graph_revision(&self) -> u64 {
        self.graph_revision
    }

    /// Returns the frozen RFC 3339 policy-evaluation time.
    pub fn effective_as_of(&self) -> &str {
        &self.effective_as_of
    }

    /// Returns the frozen evaluation time as Unix milliseconds.
    pub fn effective_as_of_unix_ms(&self) -> i64 {
        self.effective_as_of_unix_ms
    }

    /// Returns the inclusive default warning cutoff as Unix milliseconds.
    pub fn warning_cutoff_unix_ms(&self) -> i64 {
        self.warning_cutoff_unix_ms
    }
}

/// Page and population evidence returned by an indexed lifecycle reader.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedLifecyclePage {
    /// At most the prepared limit of projected lifecycle resources.
    pub resources: Vec<ProjectedResource>,
    /// Population-wide aggregates computed by the index.
    pub aggregates: LifecycleAggregates,
    /// Total lifecycle entities in the indexed source scope.
    pub lifecycle_entities: u64,
    /// Oldest matched observation time computed by the index.
    pub oldest_observed_at: Option<String>,
    /// Newest matched observation time computed by the index.
    pub newest_observed_at: Option<String>,
    /// Whether an earlier keyset page exists.
    pub has_previous: bool,
    /// Whether a later keyset page exists.
    pub has_next: bool,
    /// Graph revision actually read by the index.
    pub graph_revision: u64,
    /// Whether the index observed revision change during the read.
    pub graph_changed: bool,
}

/// Validates a public query and compiles it for an indexed graph adapter.
///
/// Preparation binds a continuation token to the exact normalized filters and graph
/// revision. The first page establishes `as_of`; later pages reuse that time and are
/// accepted for at most 15 minutes, preventing policy state from drifting mid-chain.
///
/// # Errors
///
/// Returns an error for invalid limits, excessive filter cardinality, foreign owner
/// URNs, inconsistent locators, malformed or stale cursors, filter mismatch, or an
/// invalid evaluation time.
pub fn prepare_indexed_query(
    tenant_id: &TenantId,
    query: &LifecycleQuery,
    as_of: &str,
    graph_revision: u64,
) -> Result<PreparedLifecycleQuery, LifecycleError> {
    let limit = query.limit.unwrap_or(DEFAULT_QUERY_LIMIT);
    if limit == 0 || limit > MAX_QUERY_LIMIT {
        return Err(LifecycleError::InvalidValue(format!(
            "limit must be between 1 and {MAX_QUERY_LIMIT}"
        )));
    }
    for (field, count) in [
        ("subject_kinds", query.subject_kinds.len()),
        ("states", query.states.len()),
        ("owner_urns", query.owner_urns.len()),
    ] {
        if count > MAX_QUERY_FILTER_VALUES {
            return Err(LifecycleError::InvalidValue(format!(
                "{field} exceeds {MAX_QUERY_FILTER_VALUES} values"
            )));
        }
    }
    let requested_as_of = parse_time(as_of, "as_of")?;
    let expires_before_unix_ms = query
        .expires_before
        .as_deref()
        .map(timestamp_millis_from_rfc3339)
        .transpose()?;
    for owner in &query.owner_urns {
        require_tenant_urn(tenant_id.as_str(), owner)?;
    }
    let locator_urn = query
        .subject_locator
        .as_ref()
        .map(|locator| {
            if !query.subject_kinds.is_empty()
                && !query.subject_kinds.contains(&locator.subject_kind)
            {
                return Err(LifecycleError::InvalidValue(
                    "subject_locator kind does not match subject_kinds".to_owned(),
                ));
            }
            canonical_resource_urn(
                tenant_id.as_str(),
                locator.subject_kind,
                &locator.authority_id,
                &locator.stable_locator,
            )
        })
        .transpose()?;
    let filter_digest = query_filter_digest(query, limit, locator_urn.as_deref());
    let cursor = query
        .page_token
        .as_deref()
        .map(decode_page_token)
        .transpose()?;
    if let Some(cursor) = cursor.as_ref() {
        if cursor.graph_revision != graph_revision {
            return Err(LifecycleError::InvalidValue(
                "page_token graph revision is stale".to_owned(),
            ));
        }
        if cursor.filter_digest != filter_digest {
            return Err(LifecycleError::InvalidValue(
                "page_token does not match lifecycle filters".to_owned(),
            ));
        }
    }
    // Cursor time, rather than the newest request time, freezes expiry evaluation
    // across forward and backward navigation.
    let effective_as_of = cursor
        .as_ref()
        .map(|cursor| cursor.as_of.as_str())
        .unwrap_or(as_of)
        .to_owned();
    let effective_time = cursor
        .as_ref()
        .map(|cursor| parse_time(&cursor.as_of, "page_token as_of"))
        .transpose()?
        .unwrap_or(requested_as_of);
    if effective_time > requested_as_of || requested_as_of - effective_time > MAX_CURSOR_AGE {
        return Err(LifecycleError::InvalidValue(
            "page_token evaluation time is expired or in the future".to_owned(),
        ));
    }
    let mut subject_kinds = query.subject_kinds.clone();
    subject_kinds.sort_unstable_by_key(|kind| kind.as_str());
    subject_kinds.dedup();
    let mut states = query.states.clone();
    states.sort_unstable_by_key(|state| state_name(*state));
    states.dedup();
    let mut owner_urns = query.owner_urns.clone();
    owner_urns.sort_unstable();
    owner_urns.dedup();
    let effective_as_of_unix_ms = i64::try_from(effective_time.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| LifecycleError::Invalid("as_of"))?;
    let warning_cutoff_unix_ms = effective_as_of_unix_ms.saturating_add(
        i64::from(DEFAULT_WARNING_WINDOW_DAYS).saturating_mul(24 * 60 * 60 * 1_000),
    );
    Ok(PreparedLifecycleQuery {
        limit,
        subject_kinds,
        states,
        owner_urns,
        expires_before_unix_ms,
        findings_only: query.findings_only,
        locator_urn,
        direction: cursor.as_ref().map_or(KeysetDirection::Forward, |cursor| {
            match cursor.direction {
                CursorDirection::Forward => KeysetDirection::Forward,
                CursorDirection::Backward => KeysetDirection::Backward,
            }
        }),
        cursor_subject_urn: cursor.map(|cursor| cursor.subject_urn),
        graph_revision,
        effective_as_of,
        effective_as_of_unix_ms,
        warning_cutoff_unix_ms,
        filter_digest,
    })
}

/// Converts one indexed graph page into the public lifecycle read model.
///
/// The adapter owns filtering and aggregate computation; this boundary revalidates
/// each returned resource, rejects duplicate stable identities, derives findings and
/// actions, and emits navigation tokens only when the graph revision stayed stable.
/// Indexed aggregates remain exact across ordinary page truncation, but are marked
/// inexact when the graph changed during the read.
///
/// # Errors
///
/// Returns an error when the adapter exceeds the prepared limit, returns a non-
/// lifecycle or invalid resource, duplicates an identity, or supplies data that
/// cannot be converted into the public record contract.
pub fn finalize_indexed_query(
    tenant_id: &TenantId,
    prepared: &PreparedLifecycleQuery,
    mut page: IndexedLifecyclePage,
) -> Result<QueryResult, LifecycleError> {
    if page.resources.len() > prepared.limit {
        return Err(LifecycleError::InvalidValue(
            "indexed lifecycle page exceeds requested limit".to_owned(),
        ));
    }
    let mut candidates = page
        .resources
        .drain(..)
        .map(|resource| {
            let source_runtime_id = resource
                .properties
                .get("source_runtime_id")
                .cloned()
                .unwrap_or_default();
            let source_collection_id = resource
                .properties
                .get("source_collection_id")
                .cloned()
                .unwrap_or_default();
            let observation = Observation::from_graph(resource)?.ok_or_else(|| {
                LifecycleError::InvalidValue(
                    "indexed lifecycle page contains a non-lifecycle resource".to_owned(),
                )
            })?;
            observation.validate(tenant_id)?;
            let evaluation = evaluate(
                &observation,
                &prepared.effective_as_of,
                DEFAULT_WARNING_WINDOW_DAYS,
            )?;
            Ok(Candidate {
                observation,
                evaluation,
                source_runtime_id,
                source_collection_id,
            })
        })
        .collect::<Result<Vec<_>, LifecycleError>>()?;
    candidates.sort_unstable_by(|left, right| {
        left.observation
            .subject_ref
            .id
            .cmp(&right.observation.subject_ref.id)
    });
    if candidates
        .windows(2)
        .any(|pair| pair[0].observation.subject_ref.id == pair[1].observation.subject_ref.id)
    {
        return Err(LifecycleError::InvalidValue(
            "duplicate stable lifecycle subject identity".to_owned(),
        ));
    }
    let records = candidates
        .into_iter()
        .map(|candidate| lifecycle_record(tenant_id, candidate, &prepared.effective_as_of))
        .collect::<Result<Vec<_>, _>>()?;
    // A revision mismatch is equivalent to an observed graph change even if the
    // adapter failed to set its explicit graph_changed flag.
    let graph_changed = page.graph_changed || page.graph_revision != prepared.graph_revision;
    let previous_page_token = (!graph_changed && page.has_previous)
        .then(|| records.first())
        .flatten()
        .map(|record| {
            encode_page_token(&PageCursor {
                direction: CursorDirection::Backward,
                graph_revision: page.graph_revision,
                as_of: prepared.effective_as_of.clone(),
                filter_digest: prepared.filter_digest.clone(),
                subject_urn: record.observation.subject_ref.id.clone(),
            })
        });
    let next_page_token = (!graph_changed && page.has_next)
        .then(|| records.last())
        .flatten()
        .map(|record| {
            encode_page_token(&PageCursor {
                direction: CursorDirection::Forward,
                graph_revision: page.graph_revision,
                as_of: prepared.effective_as_of.clone(),
                filter_digest: prepared.filter_digest.clone(),
                subject_urn: record.observation.subject_ref.id.clone(),
            })
        });
    let page_truncated = page.has_previous || page.has_next;
    let coverage_reason = if graph_changed {
        CoverageReason::GraphChanged
    } else {
        CoverageReason::Complete
    };
    page.aggregates.counts_are_exact = !graph_changed;
    Ok(QueryResult {
        records,
        next_page_token,
        previous_page_token,
        truncated: page_truncated || graph_changed,
        as_of: prepared.effective_as_of.clone(),
        aggregates: page.aggregates,
        metadata: QueryMetadata {
            coverage: QueryCoverage {
                complete: !graph_changed,
                truncated: graph_changed,
                scanned_entities: 0,
                lifecycle_entities: page.lifecycle_entities,
                graph_revision: page.graph_revision,
                reason: coverage_reason,
            },
            freshness: QueryFreshness {
                as_of: prepared.effective_as_of.clone(),
                oldest_observed_at: page.oldest_observed_at,
                newest_observed_at: page.newest_observed_at,
            },
            page_truncated,
        },
    })
}

/// Validated observation plus derived and projection provenance used during paging.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Candidate {
    observation: Observation,
    evaluation: PolicyEvaluation,
    source_runtime_id: String,
    source_collection_id: String,
}

/// Compact direction stored inside the v2 page-token wire format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CursorDirection {
    Forward,
    Backward,
}

/// Decoded keyset cursor before graph, filter, and age validation.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PageCursor {
    direction: CursorDirection,
    graph_revision: u64,
    as_of: String,
    filter_digest: String,
    subject_urn: String,
}

/// Executes a bounded in-memory lifecycle query with complete source coverage.
///
/// This convenience entry point treats every supplied entity as scanned and delegates
/// to [`query_records_with_source`]. Callers with truncation or graph-revision evidence
/// must use the explicit source variant.
pub fn query_records(
    tenant_id: &TenantId,
    query: &LifecycleQuery,
    entities: Vec<ProjectedResource>,
    as_of: &str,
) -> Result<QueryResult, LifecycleError> {
    let source = QuerySource {
        scanned_entities: entities.len(),
        ..QuerySource::default()
    };
    query_records_with_source(tenant_id, query, entities, as_of, source)
}

/// Resolves one current open finding from its projected lifecycle subject.
///
/// A compliant subject returns `Ok(None)`. A nonmatching or foreign finding URN is an
/// error so callers cannot attach one subject's current state to another finding.
pub fn resolve_finding_record(
    tenant_id: &TenantId,
    finding_urn: &str,
    resource: ProjectedResource,
    as_of: &str,
    graph_revision: u64,
) -> Result<Option<LifecycleRecord>, LifecycleError> {
    require_tenant_urn(tenant_id.as_str(), finding_urn)?;
    let mut result = query_records_with_source(
        tenant_id,
        &LifecycleQuery {
            findings_only: true,
            limit: Some(1),
            ..LifecycleQuery::default()
        },
        vec![resource],
        as_of,
        QuerySource {
            scanned_entities: 1,
            graph_revision,
            ..QuerySource::default()
        },
    )?;
    let Some(record) = result.records.pop() else {
        return Ok(None);
    };
    if record
        .findings
        .first()
        .is_none_or(|finding| finding.finding_ref.id != finding_urn)
    {
        return Err(LifecycleError::InvalidValue(
            "lifecycle finding identity does not match the current subject".to_owned(),
        ));
    }
    Ok(Some(record))
}

/// Filters, evaluates, aggregates, and keyset-pages an in-memory graph scan.
///
/// Aggregates describe the entire filtered candidate population before page slicing.
/// Page truncation, source scan truncation, and graph change are reported separately.
/// Navigation tokens are suppressed after a graph change because their keyset view is
/// no longer stable.
///
/// # Errors
///
/// Returns an error for invalid query bounds, tenant references, locator or cursor
/// mismatch, expired cursor time, malformed lifecycle projections, duplicate stable
/// identities, or count/time conversion failure.
pub fn query_records_with_source(
    tenant_id: &TenantId,
    query: &LifecycleQuery,
    entities: Vec<ProjectedResource>,
    as_of: &str,
    source: QuerySource,
) -> Result<QueryResult, LifecycleError> {
    let limit = query.limit.unwrap_or(DEFAULT_QUERY_LIMIT);
    if limit == 0 || limit > MAX_QUERY_LIMIT {
        return Err(LifecycleError::InvalidValue(format!(
            "limit must be between 1 and {MAX_QUERY_LIMIT}"
        )));
    }
    for (field, count) in [
        ("subject_kinds", query.subject_kinds.len()),
        ("states", query.states.len()),
        ("owner_urns", query.owner_urns.len()),
    ] {
        if count > MAX_QUERY_FILTER_VALUES {
            return Err(LifecycleError::InvalidValue(format!(
                "{field} exceeds {MAX_QUERY_FILTER_VALUES} values"
            )));
        }
    }
    let requested_as_of = parse_time(as_of, "as_of")?;
    let expires_before = query
        .expires_before
        .as_deref()
        .map(|cutoff| parse_time(cutoff, "expires_before"))
        .transpose()?;
    for owner in &query.owner_urns {
        require_tenant_urn(tenant_id.as_str(), owner)?;
    }
    let locator_urn = query
        .subject_locator
        .as_ref()
        .map(|locator| {
            if !query.subject_kinds.is_empty()
                && !query.subject_kinds.contains(&locator.subject_kind)
            {
                return Err(LifecycleError::InvalidValue(
                    "subject_locator kind does not match subject_kinds".to_owned(),
                ));
            }
            canonical_resource_urn(
                tenant_id.as_str(),
                locator.subject_kind,
                &locator.authority_id,
                &locator.stable_locator,
            )
        })
        .transpose()?;
    let filter_digest = query_filter_digest(query, limit, locator_urn.as_deref());
    let page_cursor = query
        .page_token
        .as_deref()
        .map(decode_page_token)
        .transpose()?;
    if let Some(cursor) = page_cursor.as_ref() {
        if cursor.graph_revision != source.graph_revision {
            return Err(LifecycleError::InvalidValue(
                "page_token graph revision is stale".to_owned(),
            ));
        }
        if cursor.filter_digest != filter_digest {
            return Err(LifecycleError::InvalidValue(
                "page_token does not match lifecycle filters".to_owned(),
            ));
        }
    }
    // Freeze policy time to the cursor's first-page instant while still requiring
    // the current request time to advance no more than the allowed cursor age.
    let effective_as_of = page_cursor
        .as_ref()
        .map(|cursor| cursor.as_of.as_str())
        .unwrap_or(as_of);
    let effective_as_of_time = page_cursor
        .as_ref()
        .map(|cursor| parse_time(&cursor.as_of, "page_token as_of"))
        .transpose()?
        .unwrap_or(requested_as_of);
    if effective_as_of_time > requested_as_of
        || requested_as_of - effective_as_of_time > MAX_CURSOR_AGE
    {
        return Err(LifecycleError::InvalidValue(
            "page_token evaluation time is expired or in the future".to_owned(),
        ));
    }

    // Counts and freshness are accumulated before page slicing so aggregates cover
    // the matched population rather than only the visible page.
    let mut candidates = Vec::new();
    let mut lifecycle_entities = 0_u64;
    let mut matched_findings = 0_u64;
    let mut subject_kind_counts = [0_u64; 2];
    let mut state_counts = [0_u64; 7];
    let mut policy_state_counts = [0_u64; 4];
    let mut oldest_observed_at: Option<OffsetDateTime> = None;
    let mut newest_observed_at: Option<OffsetDateTime> = None;
    for entity in entities {
        let source_runtime_id = entity
            .properties
            .get("source_runtime_id")
            .cloned()
            .unwrap_or_default();
        let source_collection_id = entity
            .properties
            .get("source_collection_id")
            .cloned()
            .unwrap_or_default();
        let Some(observation) = Observation::from_graph(entity)? else {
            continue;
        };
        lifecycle_entities = lifecycle_entities.saturating_add(1);
        observation.validate(tenant_id)?;
        if locator_urn
            .as_deref()
            .is_some_and(|subject_urn| observation.subject_ref.id != subject_urn)
        {
            continue;
        }
        if (!query.subject_kinds.is_empty()
            && !query.subject_kinds.contains(&observation.subject_kind))
            || (!query.states.is_empty() && !query.states.contains(&observation.state))
            || (!query.owner_urns.is_empty()
                && observation
                    .owner_urn
                    .as_ref()
                    .is_none_or(|owner| !query.owner_urns.contains(owner)))
            || expires_before.is_some_and(|cutoff| {
                observation
                    .expires_at
                    .as_deref()
                    .and_then(|value| parse_time(value, "expires_at").ok())
                    .is_none_or(|expiry| expiry >= cutoff)
            })
        {
            continue;
        }
        let evaluation = evaluate(&observation, effective_as_of, DEFAULT_WARNING_WINDOW_DAYS)?;
        if query.findings_only && !evaluation.has_finding() {
            continue;
        }
        let observed_at = parse_time(&observation.observed_at, "observed_at")?;
        oldest_observed_at =
            Some(oldest_observed_at.map_or(observed_at, |current| current.min(observed_at)));
        newest_observed_at =
            Some(newest_observed_at.map_or(observed_at, |current| current.max(observed_at)));
        subject_kind_counts[subject_kind_index(observation.subject_kind)] =
            subject_kind_counts[subject_kind_index(observation.subject_kind)].saturating_add(1);
        state_counts[state_index(observation.state)] =
            state_counts[state_index(observation.state)].saturating_add(1);
        let policy_state = policy_state(&evaluation)?;
        policy_state_counts[policy_state_index(policy_state)] =
            policy_state_counts[policy_state_index(policy_state)].saturating_add(1);
        if evaluation.has_finding() {
            matched_findings = matched_findings.saturating_add(1);
        }
        candidates.push(Candidate {
            observation,
            evaluation,
            source_runtime_id,
            source_collection_id,
        });
    }
    candidates.sort_unstable_by(|left, right| {
        left.observation
            .subject_ref
            .id
            .cmp(&right.observation.subject_ref.id)
    });
    if candidates
        .windows(2)
        .any(|pair| pair[0].observation.subject_ref.id == pair[1].observation.subject_ref.id)
    {
        return Err(LifecycleError::InvalidValue(
            "duplicate stable lifecycle subject identity".to_owned(),
        ));
    }
    let matched_records = u64::try_from(candidates.len())
        .map_err(|_| LifecycleError::InvalidValue("matched record count exceeds u64".to_owned()))?;
    let (start, end) = page_bounds(&candidates, page_cursor.as_ref(), limit);
    let has_previous = start > 0;
    let has_next = end < candidates.len();
    let records = candidates
        .drain(start..end)
        .map(|candidate| lifecycle_record(tenant_id, candidate, effective_as_of))
        .collect::<Result<Vec<_>, _>>()?;
    let previous_page_token = (!source.graph_changed && has_previous)
        .then(|| records.first())
        .flatten()
        .map(|record| {
            encode_page_token(&PageCursor {
                direction: CursorDirection::Backward,
                graph_revision: source.graph_revision,
                as_of: effective_as_of.to_owned(),
                filter_digest: filter_digest.clone(),
                subject_urn: record.observation.subject_ref.id.clone(),
            })
        });
    let next_page_token = (!source.graph_changed && has_next)
        .then(|| records.last())
        .flatten()
        .map(|record| {
            encode_page_token(&PageCursor {
                direction: CursorDirection::Forward,
                graph_revision: source.graph_revision,
                as_of: effective_as_of.to_owned(),
                filter_digest: filter_digest.clone(),
                subject_urn: record.observation.subject_ref.id.clone(),
            })
        });
    let page_truncated = has_previous || has_next;
    let coverage_reason = if source.graph_changed {
        CoverageReason::GraphChanged
    } else if source.truncated {
        CoverageReason::ScanLimit
    } else {
        CoverageReason::Complete
    };
    let coverage_complete = coverage_reason == CoverageReason::Complete;
    Ok(QueryResult {
        records,
        next_page_token,
        previous_page_token,
        truncated: page_truncated || !coverage_complete,
        as_of: effective_as_of.to_owned(),
        aggregates: LifecycleAggregates {
            counts_are_exact: coverage_complete,
            matched_records,
            matched_findings,
            subject_kind_counts: [SubjectKind::Credential, SubjectKind::Certificate]
                .into_iter()
                .enumerate()
                .map(|(index, subject_kind)| SubjectKindCount {
                    subject_kind,
                    count: subject_kind_counts[index],
                })
                .collect(),
            state_counts: [
                LifecycleState::Active,
                LifecycleState::Expiring,
                LifecycleState::Expired,
                LifecycleState::Rotated,
                LifecycleState::Revoked,
                LifecycleState::Inactive,
                LifecycleState::Unknown,
            ]
            .into_iter()
            .enumerate()
            .map(|(index, state)| StateCount {
                state,
                count: state_counts[index],
            })
            .collect(),
            policy_state_counts: [
                PolicyState::Compliant,
                PolicyState::Expiring,
                PolicyState::Expired,
                PolicyState::Unknown,
            ]
            .into_iter()
            .enumerate()
            .map(|(index, policy_state)| PolicyStateCount {
                policy_state,
                count: policy_state_counts[index],
            })
            .collect(),
        },
        metadata: QueryMetadata {
            coverage: QueryCoverage {
                complete: coverage_complete,
                truncated: source.truncated,
                scanned_entities: u64::try_from(source.scanned_entities).map_err(|_| {
                    LifecycleError::InvalidValue("scanned entity count exceeds u64".to_owned())
                })?,
                lifecycle_entities,
                graph_revision: source.graph_revision,
                reason: coverage_reason,
            },
            freshness: QueryFreshness {
                as_of: effective_as_of_time
                    .format(&Rfc3339)
                    .map_err(|_| LifecycleError::Invalid("as_of"))?,
                oldest_observed_at: format_optional_time(oldest_observed_at)?,
                newest_observed_at: format_optional_time(newest_observed_at)?,
            },
            page_truncated,
        },
    })
}

/// Derives findings and action routes for one validated query candidate.
fn lifecycle_record(
    tenant_id: &TenantId,
    candidate: Candidate,
    as_of: &str,
) -> Result<LifecycleRecord, LifecycleError> {
    let mut findings = Vec::new();
    let mut action_routes = Vec::new();
    if candidate.evaluation.has_finding() {
        let finding_ref = ResourceRef {
            kind: "finding".to_owned(),
            id: canonical_finding_urn(tenant_id.as_str(), &candidate.observation.subject_ref.id)?,
            revision: candidate.observation.subject_ref.revision.clone(),
            state: Some("open".to_owned()),
        };
        findings.push(FindingBinding {
            finding_ref: finding_ref.clone(),
            subject_ref: candidate.observation.subject_ref.clone(),
            finding_kind: format!("{}_expiry", candidate.observation.subject_kind.as_str()),
            status: "open".to_owned(),
            evidence_claim_refs: candidate.observation.evidence_claim_refs.clone(),
        });
        action_routes.push(action_route(
            tenant_id,
            finding_ref,
            &candidate.observation,
            true,
        )?);
    }
    Ok(LifecycleRecord {
        observation: candidate.observation,
        policy_evaluations: vec![candidate.evaluation],
        findings,
        action_routes,
        projected_at: as_of.to_owned(),
        source_runtime_id: candidate.source_runtime_id,
        source_collection_id: candidate.source_collection_id,
    })
}

/// Computes an exclusive stable-identity keyset window in either direction.
///
/// A missing cursor subject is treated as an insertion point. Forward navigation
/// skips an exact cursor match; backward navigation ends immediately before it.
fn page_bounds(
    candidates: &[Candidate],
    cursor: Option<&PageCursor>,
    limit: usize,
) -> (usize, usize) {
    match cursor {
        None => (0, candidates.len().min(limit)),
        Some(cursor) => {
            let position = candidates.partition_point(|candidate| {
                candidate.observation.subject_ref.id.as_str() < cursor.subject_urn.as_str()
            });
            match cursor.direction {
                CursorDirection::Forward => {
                    let start = if candidates[position..].first().is_some_and(|candidate| {
                        candidate.observation.subject_ref.id == cursor.subject_urn
                    }) {
                        position.saturating_add(1)
                    } else {
                        position
                    };
                    (start, start.saturating_add(limit).min(candidates.len()))
                }
                CursorDirection::Backward => {
                    let end = position;
                    (end.saturating_sub(limit), end)
                }
            }
        }
    }
}

/// Digests the normalized filters that define cursor compatibility.
///
/// This digest detects accidental or malicious filter substitution but is not an
/// authorization token or MAC. Tenant isolation is enforced independently by the
/// authenticated graph scope and tenant-scoped references.
fn query_filter_digest(query: &LifecycleQuery, limit: usize, locator_urn: Option<&str>) -> String {
    let subject_kinds = canonical_filter_values(
        query
            .subject_kinds
            .iter()
            .map(|kind| kind.as_str())
            .collect(),
    );
    let states = canonical_filter_values(
        query
            .states
            .iter()
            .map(|state| state_name(*state))
            .collect(),
    );
    let owners = canonical_filter_values(query.owner_urns.iter().map(String::as_str).collect());
    let raw = format!(
        "{subject_kinds}\0{states}\0{}\0{}\0{}\0{limit}\0{}",
        owners,
        query.expires_before.as_deref().unwrap_or_default(),
        query.findings_only,
        locator_urn.unwrap_or_default(),
    );
    hex_encode(&Sha256::digest(raw.as_bytes()))
}

/// Sorts and deduplicates a set-valued filter for stable digest encoding.
fn canonical_filter_values(mut values: Vec<&str>) -> String {
    values.sort_unstable();
    values.dedup();
    values.join(",")
}

/// Encodes a v2 cursor as lowercase hex over a NUL-delimited field sequence.
///
/// The token is opaque navigation state, not a secret and not an authorization
/// credential. Semantic graph, filter, and age checks occur during query preparation.
fn encode_page_token(cursor: &PageCursor) -> String {
    let direction = match cursor.direction {
        CursorDirection::Forward => "f",
        CursorDirection::Backward => "b",
    };
    let raw = format!(
        "{direction}\0{}\0{}\0{}\0{}",
        cursor.graph_revision, cursor.as_of, cursor.filter_digest, cursor.subject_urn
    );
    let mut encoded = String::with_capacity(3 + raw.len() * 2);
    encoded.push_str("v2.");
    encoded.push_str(&hex_encode(raw.as_bytes()));
    encoded
}

/// Parses and bounds the v2 cursor wire format before semantic validation.
///
/// Length is checked before hex allocation. The parser requires exactly five fields,
/// a known direction, valid time, digest-shaped filter binding, and bounded subject
/// identity; graph revision, filter equality, and age are checked by query preparation.
fn decode_page_token(token: &str) -> Result<PageCursor, LifecycleError> {
    if token.len() > MAX_PAGE_TOKEN_CHARS {
        return Err(LifecycleError::InvalidValue(
            "page_token exceeds maximum length".to_owned(),
        ));
    }
    let encoded = token
        .strip_prefix("v2.")
        .filter(|encoded| !encoded.is_empty() && encoded.len() % 2 == 0)
        .ok_or_else(|| LifecycleError::InvalidValue("invalid page_token".to_owned()))?;
    let bytes = hex_decode(encoded)?;
    let raw = String::from_utf8(bytes)
        .map_err(|_| LifecycleError::InvalidValue("invalid page_token".to_owned()))?;
    let mut parts = raw.split('\0');
    let direction = match parts.next() {
        Some("f") => CursorDirection::Forward,
        Some("b") => CursorDirection::Backward,
        _ => {
            return Err(LifecycleError::InvalidValue(
                "invalid page_token".to_owned(),
            ));
        }
    };
    let graph_revision = parts
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| LifecycleError::InvalidValue("invalid page_token".to_owned()))?;
    let as_of = parts
        .next()
        .filter(|value| parse_time(value, "page_token as_of").is_ok())
        .ok_or_else(|| LifecycleError::InvalidValue("invalid page_token".to_owned()))?;
    let filter_digest = parts
        .next()
        .filter(|value| value.len() == 64)
        .ok_or_else(|| LifecycleError::InvalidValue("invalid page_token".to_owned()))?;
    let subject_urn = parts
        .next()
        .filter(|value| !value.is_empty() && value.len() <= MAX_CURSOR_SUBJECT_URN_BYTES)
        .ok_or_else(|| LifecycleError::InvalidValue("invalid page_token".to_owned()))?;
    if parts.next().is_some() {
        return Err(LifecycleError::InvalidValue(
            "invalid page_token".to_owned(),
        ));
    }
    Ok(PageCursor {
        direction,
        graph_revision,
        as_of: as_of.to_owned(),
        filter_digest: filter_digest.to_owned(),
        subject_urn: subject_urn.to_owned(),
    })
}

/// Encodes bytes as lowercase hexadecimal without padding or separators.
fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

/// Decodes an already length-bounded even-width hexadecimal token body.
fn hex_decode(encoded: &str) -> Result<Vec<u8>, LifecycleError> {
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|value| u8::from_str_radix(value, 16).ok())
                .ok_or_else(|| LifecycleError::InvalidValue("invalid page_token".to_owned()))
        })
        .collect()
}

/// Maps the closed subject enum to its aggregate-array slot.
fn subject_kind_index(kind: SubjectKind) -> usize {
    match kind {
        SubjectKind::Credential => 0,
        SubjectKind::Certificate => 1,
    }
}

/// Maps the closed observed-state enum to its aggregate-array slot.
fn state_index(state: LifecycleState) -> usize {
    match state {
        LifecycleState::Active => 0,
        LifecycleState::Expiring => 1,
        LifecycleState::Expired => 2,
        LifecycleState::Rotated => 3,
        LifecycleState::Revoked => 4,
        LifecycleState::Inactive => 5,
        LifecycleState::Unknown => 6,
    }
}

/// Converts the policy wire string back into the closed aggregate enum.
fn policy_state(evaluation: &PolicyEvaluation) -> Result<PolicyState, LifecycleError> {
    match evaluation.state {
        "compliant" => Ok(PolicyState::Compliant),
        "expiring" => Ok(PolicyState::Expiring),
        "expired" => Ok(PolicyState::Expired),
        "unknown" => Ok(PolicyState::Unknown),
        _ => Err(LifecycleError::Invalid("policy evaluation state")),
    }
}

/// Maps the closed policy enum to its aggregate-array slot.
fn policy_state_index(state: PolicyState) -> usize {
    match state {
        PolicyState::Compliant => 0,
        PolicyState::Expiring => 1,
        PolicyState::Expired => 2,
        PolicyState::Unknown => 3,
    }
}

/// Formats an optional observation bound as RFC 3339 without inventing a default.
fn format_optional_time(value: Option<OffsetDateTime>) -> Result<Option<String>, LifecycleError> {
    value
        .map(|value| {
            value
                .format(&Rfc3339)
                .map_err(|_| LifecycleError::Invalid("observed_at"))
        })
        .transpose()
}

/// Constructs the stable tenant-scoped URN for a credential or certificate slot.
///
/// Tenant, authority, and locator must be non-empty with no surrounding whitespace.
/// Each component is percent-encoded independently, preventing delimiter aliases.
/// Material revision is deliberately absent from stable slot identity.
///
/// # Errors
///
/// Returns an error for invalid components or a URN too large for page cursors.
pub fn canonical_resource_urn(
    tenant_id: &str,
    kind: SubjectKind,
    authority_id: &str,
    stable_locator: &str,
) -> Result<String, LifecycleError> {
    for (field, value) in [
        ("tenant_id", tenant_id),
        ("authority_id", authority_id),
        ("stable_locator", stable_locator),
    ] {
        if value.trim().is_empty() || value.trim() != value {
            return Err(LifecycleError::Invalid(field));
        }
    }
    let urn = format!(
        "urn:cerebro:{}:{}:{}:{}",
        encode_segment(tenant_id),
        kind.as_str(),
        encode_segment(authority_id),
        encode_segment(stable_locator)
    );
    if urn.len() > MAX_CURSOR_SUBJECT_URN_BYTES {
        return Err(LifecycleError::InvalidValue(
            "canonical resource URN exceeds maximum length".to_owned(),
        ));
    }
    Ok(urn)
}

/// Constructs a tenant-scoped finding URN from an opaque finding identity.
pub fn canonical_finding_urn(tenant_id: &str, finding_id: &str) -> Result<String, LifecycleError> {
    canonical_single_id_urn(tenant_id, "finding", finding_id)
}

/// Constructs the tenant-specific prefix used to recognize lifecycle finding URNs.
pub fn canonical_finding_urn_prefix(tenant_id: &str) -> Result<String, LifecycleError> {
    if tenant_id.trim().is_empty() {
        return Err(LifecycleError::Invalid("URN component"));
    }
    Ok(format!(
        "urn:cerebro:{}:finding:",
        encode_segment(tenant_id)
    ))
}

/// Constructs a tenant-scoped remediation-outcome URN from an opaque outcome identity.
pub fn canonical_remediation_outcome_urn(
    tenant_id: &str,
    outcome_id: &str,
) -> Result<String, LifecycleError> {
    canonical_single_id_urn(tenant_id, "remediation_outcome", outcome_id)
}

/// Constructs a canonical tenant/kind/opaque-id URN with component encoding.
fn canonical_single_id_urn(
    tenant_id: &str,
    kind: &str,
    id: &str,
) -> Result<String, LifecycleError> {
    if tenant_id.trim().is_empty() || id.trim().is_empty() {
        return Err(LifecycleError::Invalid("URN component"));
    }
    Ok(format!(
        "urn:cerebro:{}:{kind}:{}",
        encode_segment(tenant_id),
        encode_segment(id)
    ))
}

/// Requires a nonempty object below the authenticated tenant URN prefix.
fn require_tenant_urn(tenant_id: &str, value: &str) -> Result<(), LifecycleError> {
    let expected = format!("urn:cerebro:{}:", encode_segment(tenant_id));
    if !value.starts_with(&expected) || value.len() == expected.len() {
        return Err(LifecycleError::Invalid("tenant-scoped URN"));
    }
    Ok(())
}

/// Percent-encodes one URN component using the RFC 3986 unreserved set.
///
/// Encoding operates on UTF-8 bytes and uses uppercase hex, producing one canonical
/// spelling for delimiters and non-ASCII text.
fn encode_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// Parses one strict RFC 3339 field and preserves its name in the rejection.
fn parse_time(value: &str, field: &'static str) -> Result<OffsetDateTime, LifecycleError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| LifecycleError::Invalid(field))
}

/// Validates and formats a protobuf timestamp as RFC 3339.
///
/// Negative epoch seconds are rejected by this v1 contract, and nanoseconds must be
/// within the protobuf range before conversion.
fn wire_timestamp(
    value: &prost_types::Timestamp,
    field: &'static str,
) -> Result<String, LifecycleError> {
    if value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos) {
        return Err(LifecycleError::Invalid(field));
    }
    OffsetDateTime::from_unix_timestamp(value.seconds)
        .and_then(|timestamp| timestamp.replace_nanosecond(value.nanos as u32))
        .map_err(|_| LifecycleError::Invalid(field))?
        .format(&Rfc3339)
        .map_err(|_| LifecycleError::Invalid(field))
}

/// Converts RFC 3339 to signed Unix milliseconds without saturating overflow.
pub fn timestamp_millis_from_rfc3339(value: &str) -> Result<i64, LifecycleError> {
    let timestamp = parse_time(value, "timestamp")?;
    i64::try_from(timestamp.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| LifecycleError::Invalid("timestamp"))
}

/// Converts signed Unix milliseconds to canonical RFC 3339.
pub fn rfc3339_from_timestamp_millis(value: i64) -> Result<String, LifecycleError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(value).saturating_mul(1_000_000))
        .map_err(|_| LifecycleError::Invalid("timestamp"))?
        .format(&Rfc3339)
        .map_err(|_| LifecycleError::Invalid("timestamp"))
}

/// Converts a wire reference and drops empty optional strings and routing hints.
fn resource_ref(value: WireResourceRef) -> ResourceRef {
    ResourceRef {
        kind: value.kind,
        id: value.id,
        revision: (!value.revision.trim().is_empty()).then_some(value.revision),
        state: (!value.state.trim().is_empty()).then_some(value.state),
    }
}

/// Derives a bounded graph identifier from the first 128 bits of a SHA-256 digest.
///
/// The caller provides a type-specific prefix, while the full canonical URN remains
/// in graph properties for correlation and collision diagnosis.
fn stable_entity_id(prefix: &str, value: &str) -> Result<EntityId, LifecycleError> {
    let digest = Sha256::digest(value.as_bytes());
    let suffix = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    EntityId::parse(format!("{prefix}:{suffix}")).map_err(model_error)
}

/// Adapts organizational-model validation failures without exposing internal types.
fn model_error(error: impl fmt::Display) -> LifecycleError {
    LifecycleError::InvalidValue(error.to_string())
}

/// Parses the closed lowercase subject-kind graph vocabulary.
fn parse_subject_kind(value: &str) -> Option<SubjectKind> {
    match value.trim() {
        "credential" => Some(SubjectKind::Credential),
        "certificate" => Some(SubjectKind::Certificate),
        _ => None,
    }
}

/// Parses the closed lowercase observed-state graph vocabulary.
fn parse_state(value: &str) -> Option<LifecycleState> {
    match value.trim() {
        "active" => Some(LifecycleState::Active),
        "expiring" => Some(LifecycleState::Expiring),
        "expired" => Some(LifecycleState::Expired),
        "rotated" => Some(LifecycleState::Rotated),
        "revoked" => Some(LifecycleState::Revoked),
        "inactive" => Some(LifecycleState::Inactive),
        "unknown" => Some(LifecycleState::Unknown),
        _ => None,
    }
}

/// Returns the canonical lowercase observed-state graph value.
fn state_name(value: LifecycleState) -> &'static str {
    match value {
        LifecycleState::Active => "active",
        LifecycleState::Expiring => "expiring",
        LifecycleState::Expired => "expired",
        LifecycleState::Rotated => "rotated",
        LifecycleState::Revoked => "revoked",
        LifecycleState::Inactive => "inactive",
        LifecycleState::Unknown => "unknown",
    }
}

/// Returns the canonical lowercase name for a lifecycle state.
pub fn lifecycle_state_name(value: LifecycleState) -> &'static str {
    state_name(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> TenantId {
        TenantId::parse("tenant-a").unwrap()
    }

    fn observation(state: LifecycleState, revision: &str, expires_at: Option<&str>) -> Observation {
        Observation {
            subject_ref: ResourceRef {
                kind: "credential".to_owned(),
                id: canonical_resource_urn(
                    "tenant-a",
                    SubjectKind::Credential,
                    "aws/production",
                    "deploy/signing",
                )
                .unwrap(),
                revision: Some(revision.to_owned()),
                state: None,
            },
            subject_kind: SubjectKind::Credential,
            provider: "aws".to_owned(),
            authority_id: "aws/production".to_owned(),
            stable_locator: "deploy/signing".to_owned(),
            display_name: "Deployment signing credential".to_owned(),
            state,
            observed_at: "2026-07-26T12:00:00Z".to_owned(),
            issued_at: None,
            expires_at: expires_at.map(str::to_owned),
            rotated_at: None,
            revoked_at: None,
            owner_urn: Some("urn:cerebro:tenant-a:team:security".to_owned()),
            scope_refs: Vec::new(),
            evidence_claim_refs: vec![ResourceRef {
                kind: "claim".to_owned(),
                id: "urn:cerebro:tenant-a:claim:observation-1".to_owned(),
                revision: None,
                state: None,
            }],
            attributes: BTreeMap::new(),
        }
    }

    fn projected(observation: Observation) -> ProjectedResource {
        ProjectedResource {
            agent_key: observation.subject_ref.id.clone(),
            label: observation.display_name.clone(),
            properties: projection_properties(&observation).unwrap(),
        }
    }

    fn indexed_aggregates(matched_records: u64) -> LifecycleAggregates {
        LifecycleAggregates {
            counts_are_exact: true,
            matched_records,
            matched_findings: matched_records,
            subject_kind_counts: vec![
                SubjectKindCount {
                    subject_kind: SubjectKind::Credential,
                    count: matched_records,
                },
                SubjectKindCount {
                    subject_kind: SubjectKind::Certificate,
                    count: 0,
                },
            ],
            state_counts: [
                LifecycleState::Active,
                LifecycleState::Expiring,
                LifecycleState::Expired,
                LifecycleState::Rotated,
                LifecycleState::Revoked,
                LifecycleState::Inactive,
                LifecycleState::Unknown,
            ]
            .into_iter()
            .map(|state| StateCount {
                count: u64::from(state == LifecycleState::Expired) * matched_records,
                state,
            })
            .collect(),
            policy_state_counts: [
                PolicyState::Compliant,
                PolicyState::Expiring,
                PolicyState::Expired,
                PolicyState::Unknown,
            ]
            .into_iter()
            .map(|policy_state| PolicyStateCount {
                count: u64::from(policy_state == PolicyState::Expired) * matched_records,
                policy_state,
            })
            .collect(),
        }
    }

    #[test]
    fn graph_projection_skips_incomplete_lifecycle_shaped_entities() {
        let incomplete = ProjectedResource {
            agent_key: "urn:cerebro:tenant-a:resource:unrelated".to_owned(),
            label: "Unrelated resource".to_owned(),
            properties: BTreeMap::from([("subject_kind".to_owned(), "credential".to_owned())]),
        };

        assert_eq!(Observation::from_graph(incomplete).unwrap(), None);
    }

    #[test]
    fn graph_projection_round_trips_references_and_allowed_metadata() {
        let mut original = observation(
            LifecycleState::Active,
            "key-1",
            Some("2026-08-01T12:00:00Z"),
        );
        original.scope_refs.push(ResourceRef {
            kind: "scope".to_owned(),
            id: "urn:cerebro:tenant-a:scope:production".to_owned(),
            revision: Some("scope-v2".to_owned()),
            state: Some("active".to_owned()),
        });
        original
            .attributes
            .insert("environment".to_owned(), "production".to_owned());

        let restored = Observation::from_graph(projected(original.clone()))
            .unwrap()
            .unwrap();

        assert_eq!(restored.scope_refs, original.scope_refs);
        assert_eq!(restored.evidence_claim_refs, original.evidence_claim_refs);
        assert_eq!(restored.attributes, original.attributes);
    }

    #[test]
    fn stable_slot_is_identity_and_material_is_revision() {
        let first = observation(LifecycleState::Active, "key-1", None);
        let second = observation(LifecycleState::Rotated, "key-2", None);
        assert_eq!(first.subject_ref.id, second.subject_ref.id);
        assert_ne!(first.subject_ref.revision, second.subject_ref.revision);
        assert!(first.validate(&tenant()).is_ok());
        assert!(second.validate(&tenant()).is_ok());
    }

    #[test]
    fn canonical_urn_percent_encodes_authority_and_slot() {
        assert_eq!(
            canonical_resource_urn(
                "tenant-a",
                SubjectKind::Certificate,
                "vault/prod",
                "api cert"
            )
            .unwrap(),
            "urn:cerebro:tenant-a:certificate:vault%2Fprod:api%20cert"
        );
        assert_eq!(
            canonical_finding_urn_prefix("tenant:regional/prod").unwrap(),
            "urn:cerebro:tenant%3Aregional%2Fprod:finding:"
        );
    }

    #[test]
    fn canonical_urn_disambiguates_colon_delimited_tenant_ids() {
        let parent = canonical_resource_urn(
            "acme",
            SubjectKind::Credential,
            "aws/production",
            "deploy/signing",
        )
        .unwrap();
        let child = canonical_resource_urn(
            "acme:prod",
            SubjectKind::Credential,
            "aws/production",
            "deploy/signing",
        )
        .unwrap();

        assert_ne!(parent, child);
        assert!(require_tenant_urn("acme:prod", &child).is_ok());
        assert!(require_tenant_urn("acme", &child).is_err());
    }

    #[test]
    fn policy_follows_observed_state_and_expiry_window() {
        let evaluation = evaluate(
            &observation(
                LifecycleState::Active,
                "key-1",
                Some("2026-08-01T12:00:00Z"),
            ),
            "2026-07-26T12:00:00Z",
            30,
        )
        .unwrap();
        assert_eq!(evaluation.state, "expiring");

        let rotated = evaluate(
            &observation(
                LifecycleState::Rotated,
                "key-2",
                Some("2026-07-01T12:00:00Z"),
            ),
            "2026-07-26T12:00:00Z",
            30,
        )
        .unwrap();
        assert_eq!(rotated.state, "compliant");
    }

    #[test]
    fn active_observation_without_expiry_is_unknown() {
        let evaluation = evaluate(
            &observation(LifecycleState::Active, "key-1", None),
            "2026-07-26T12:00:00Z",
            30,
        )
        .unwrap();

        assert_eq!(evaluation.state, "unknown");
        assert_eq!(evaluation.seconds_until_expiry, None);
        assert!(!evaluation.has_finding());
    }

    #[test]
    fn provider_success_cannot_close_without_fresh_complete_observation() {
        let expectation = VerificationExpectation {
            tenant_id: tenant(),
            finding_ref: ResourceRef {
                kind: "finding".to_owned(),
                id: canonical_finding_urn("tenant-a", "finding-1").unwrap(),
                revision: None,
                state: None,
            },
            remediation_outcome_ref: ResourceRef {
                kind: "remediation_outcome".to_owned(),
                id: canonical_remediation_outcome_urn("tenant-a", "outcome-1").unwrap(),
                revision: None,
                state: None,
            },
            subject_ref: observation(LifecycleState::Active, "key-1", None).subject_ref,
            source_runtime_ref: ResourceRef {
                kind: "source_runtime".to_owned(),
                id: "urn:cerebro:tenant-a:source_runtime:expiry-tracker".to_owned(),
                revision: None,
                state: None,
            },
            dispatched_at: "2026-07-26T11:00:00Z".to_owned(),
        };
        let event_ref = ResourceRef {
            kind: "event".to_owned(),
            id: "urn:cerebro:tenant-a:event:observation-2".to_owned(),
            revision: None,
            state: None,
        };
        let rotated_observation = observation(LifecycleState::Rotated, "key-2", None);
        assert_eq!(
            bind_verification(
                &rotated_observation,
                event_ref.clone(),
                expectation.source_runtime_ref.clone(),
                &expectation,
                false,
                false,
                30
            )
            .unwrap()
            .result,
            "verification_pending"
        );
        assert_eq!(
            bind_verification(
                &rotated_observation,
                event_ref,
                expectation.source_runtime_ref.clone(),
                &expectation,
                true,
                false,
                30,
            )
            .unwrap()
            .result,
            "verified_closed"
        );
        let unknown_expiry = observation(LifecycleState::Active, "key-3", None);
        assert_eq!(
            bind_verification(
                &unknown_expiry,
                ResourceRef {
                    kind: "event".to_owned(),
                    id: "urn:cerebro:tenant-a:event:observation-unknown".to_owned(),
                    revision: None,
                    state: None,
                },
                expectation.source_runtime_ref.clone(),
                &expectation,
                true,
                false,
                30,
            )
            .unwrap()
            .result,
            "verification_pending"
        );
        let foreign_runtime = ResourceRef {
            kind: "source_runtime".to_owned(),
            id: "urn:cerebro:tenant-a:source_runtime:other".to_owned(),
            revision: None,
            state: None,
        };
        assert!(
            bind_verification(
                &rotated_observation,
                ResourceRef {
                    kind: "event".to_owned(),
                    id: "urn:cerebro:tenant-a:event:observation-3".to_owned(),
                    revision: None,
                    state: None,
                },
                foreign_runtime,
                &expectation,
                true,
                false,
                30,
            )
            .is_err()
        );
    }

    #[test]
    fn metadata_allowlist_rejects_secret_material() {
        let mut candidate = observation(LifecycleState::Active, "key-1", None);
        candidate
            .attributes
            .insert("private_key".to_owned(), "not-even-a-real-key".to_owned());
        assert!(matches!(
            candidate.validate(&tenant()),
            Err(LifecycleError::SecretMaterial(_))
        ));
    }

    #[test]
    fn bounded_query_builds_finding_and_opaque_action_refs() {
        let observation = observation(
            LifecycleState::Active,
            "key-1",
            Some("2026-08-01T12:00:00Z"),
        );
        let properties = BTreeMap::from([
            (
                "resource_urn".to_owned(),
                observation.subject_ref.id.clone(),
            ),
            (
                "material_revision".to_owned(),
                observation.subject_ref.revision.clone().unwrap(),
            ),
            ("subject_kind".to_owned(), "credential".to_owned()),
            ("lifecycle_state".to_owned(), "active".to_owned()),
            ("provider".to_owned(), observation.provider),
            ("authority_id".to_owned(), observation.authority_id),
            ("stable_locator".to_owned(), observation.stable_locator),
            ("observed_at".to_owned(), observation.observed_at),
            ("expires_at".to_owned(), observation.expires_at.unwrap()),
            ("owner_urn".to_owned(), observation.owner_urn.unwrap()),
        ]);
        let result = query_records(
            &tenant(),
            &LifecycleQuery {
                findings_only: true,
                ..LifecycleQuery::default()
            },
            vec![ProjectedResource {
                agent_key: "unused".to_owned(),
                label: "Deployment signing credential".to_owned(),
                properties,
            }],
            "2026-07-26T12:00:00Z",
        )
        .unwrap();
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.records[0].findings.len(), 1);
        assert_eq!(
            result.records[0].action_routes[0].action_type,
            "rotate_credential"
        );
        assert!(
            result.records[0].action_routes[0]
                .dispatch_ref
                .id
                .starts_with("urn:cerebro:tenant-a:dispatch:")
        );
    }

    #[test]
    fn lifecycle_page_token_round_trips_stable_subject_urn() {
        let subject = "urn:cerebro:tenant-a:credential:aws%2Fproduction:deploy%2Fsigning";
        let cursor = PageCursor {
            direction: CursorDirection::Forward,
            graph_revision: 42,
            as_of: "2026-07-26T12:00:00Z".to_owned(),
            filter_digest: "a".repeat(64),
            subject_urn: subject.to_owned(),
        };
        let token = encode_page_token(&cursor);

        assert_ne!(token, subject);
        assert_eq!(decode_page_token(&token).unwrap(), cursor);
        assert!(decode_page_token("v1.not-hex").is_err());
    }

    #[test]
    fn page_token_decode_rejects_oversized_input_before_hex_allocation() {
        let oversized = format!("v2.{}", "aa".repeat(MAX_PAGE_TOKEN_CHARS));
        let error = decode_page_token(&oversized).unwrap_err();
        assert!(error.to_string().contains("maximum length"));
    }

    #[test]
    fn page_token_decode_rejects_unknown_direction_and_trailing_fields() {
        let invalid_direction = format!(
            "v2.{}",
            hex_encode(
                format!(
                    "x\0{}\0{}\0{}\0{}",
                    7,
                    "2026-07-26T12:00:00Z",
                    "a".repeat(64),
                    "urn:cerebro:tenant-a:credential:authority:slot"
                )
                .as_bytes()
            )
        );
        assert!(decode_page_token(&invalid_direction).is_err());

        let trailing_field = format!(
            "v2.{}",
            hex_encode(
                format!(
                    "f\0{}\0{}\0{}\0{}\0extra",
                    7,
                    "2026-07-26T12:00:00Z",
                    "a".repeat(64),
                    "urn:cerebro:tenant-a:credential:authority:slot"
                )
                .as_bytes()
            )
        );
        assert!(decode_page_token(&trailing_field).is_err());
    }

    #[test]
    fn bounded_query_rejects_invalid_limit_and_locator_kind_mismatch() {
        let limit_error = query_records(
            &tenant(),
            &LifecycleQuery {
                limit: Some(MAX_QUERY_LIMIT + 1),
                ..LifecycleQuery::default()
            },
            Vec::new(),
            "2026-07-26T12:00:00Z",
        )
        .unwrap_err();
        assert!(limit_error.to_string().contains("limit"));

        let locator_error = query_records(
            &tenant(),
            &LifecycleQuery {
                subject_kinds: vec![SubjectKind::Certificate],
                subject_locator: Some(SubjectLocator {
                    subject_kind: SubjectKind::Credential,
                    authority_id: "authority".to_owned(),
                    stable_locator: "slot".to_owned(),
                }),
                ..LifecycleQuery::default()
            },
            Vec::new(),
            "2026-07-26T12:00:00Z",
        )
        .unwrap_err();
        assert!(locator_error.to_string().contains("subject_locator kind"));
    }

    #[test]
    fn cursor_filter_digest_canonicalizes_set_order_and_duplicates() {
        let first = LifecycleQuery {
            subject_kinds: vec![
                SubjectKind::Certificate,
                SubjectKind::Credential,
                SubjectKind::Certificate,
            ],
            states: vec![
                LifecycleState::Expired,
                LifecycleState::Active,
                LifecycleState::Expired,
            ],
            owner_urns: vec![
                "urn:cerebro:tenant-a:team:z".to_owned(),
                "urn:cerebro:tenant-a:team:a".to_owned(),
            ],
            ..LifecycleQuery::default()
        };
        let second = LifecycleQuery {
            subject_kinds: vec![SubjectKind::Credential, SubjectKind::Certificate],
            states: vec![LifecycleState::Active, LifecycleState::Expired],
            owner_urns: vec![
                "urn:cerebro:tenant-a:team:a".to_owned(),
                "urn:cerebro:tenant-a:team:z".to_owned(),
            ],
            ..LifecycleQuery::default()
        };
        assert_eq!(
            query_filter_digest(&first, DEFAULT_QUERY_LIMIT, None),
            query_filter_digest(&second, DEFAULT_QUERY_LIMIT, None)
        );
    }

    #[test]
    fn bounded_query_filters_and_navigates_both_directions() {
        let mut first = observation(
            LifecycleState::Active,
            "key-1",
            Some("2026-08-01T12:00:00Z"),
        );
        first.stable_locator = "a/signing".to_owned();
        first.subject_ref.id = canonical_resource_urn(
            "tenant-a",
            SubjectKind::Credential,
            &first.authority_id,
            &first.stable_locator,
        )
        .unwrap();
        let mut second = observation(
            LifecycleState::Expired,
            "key-2",
            Some("2026-07-01T12:00:00Z"),
        );
        second.stable_locator = "b/signing".to_owned();
        second.subject_ref.id = canonical_resource_urn(
            "tenant-a",
            SubjectKind::Credential,
            &second.authority_id,
            &second.stable_locator,
        )
        .unwrap();
        let entities = vec![projected(second), projected(first)];

        let first_page = query_records(
            &tenant(),
            &LifecycleQuery {
                subject_kinds: vec![SubjectKind::Credential],
                owner_urns: vec!["urn:cerebro:tenant-a:team:security".to_owned()],
                findings_only: true,
                limit: Some(1),
                ..LifecycleQuery::default()
            },
            entities.clone(),
            "2026-07-26T12:00:00Z",
        )
        .unwrap();
        assert!(first_page.truncated);
        assert_eq!(first_page.records.len(), 1);

        let filter = LifecycleQuery {
            subject_kinds: vec![SubjectKind::Credential],
            owner_urns: vec!["urn:cerebro:tenant-a:team:security".to_owned()],
            findings_only: true,
            limit: Some(1),
            ..LifecycleQuery::default()
        };
        let second_page = query_records(
            &tenant(),
            &LifecycleQuery {
                page_token: first_page.next_page_token,
                ..filter.clone()
            },
            entities.clone(),
            "2026-07-26T12:00:00Z",
        )
        .unwrap();
        assert!(second_page.truncated);
        assert_eq!(second_page.records.len(), 1);
        assert_eq!(
            second_page.records[0].observation.state,
            LifecycleState::Expired
        );
        let previous_page = query_records(
            &tenant(),
            &LifecycleQuery {
                page_token: second_page.previous_page_token,
                ..filter
            },
            entities,
            "2026-07-26T12:05:00Z",
        )
        .unwrap();
        assert_eq!(
            previous_page.records[0].observation.subject_ref.id,
            first_page.records[0].observation.subject_ref.id
        );
        assert_eq!(previous_page.as_of, first_page.as_of);
    }

    #[test]
    fn page_cursor_binds_filters_and_graph_revision() {
        let entity = projected(observation(
            LifecycleState::Expired,
            "key-1",
            Some("2026-07-01T12:00:00Z"),
        ));
        let source = QuerySource {
            scanned_entities: 1,
            graph_revision: 7,
            ..QuerySource::default()
        };
        let first = query_records_with_source(
            &tenant(),
            &LifecycleQuery {
                limit: Some(1),
                ..LifecycleQuery::default()
            },
            vec![
                entity.clone(),
                projected({
                    let mut other = observation(
                        LifecycleState::Expired,
                        "key-2",
                        Some("2026-07-01T12:00:00Z"),
                    );
                    other.stable_locator = "other".to_owned();
                    other.subject_ref.id = canonical_resource_urn(
                        "tenant-a",
                        other.subject_kind,
                        &other.authority_id,
                        &other.stable_locator,
                    )
                    .unwrap();
                    other
                }),
            ],
            "2026-07-26T12:00:00Z",
            source,
        )
        .unwrap();
        let token = first.next_page_token.unwrap();
        let filter_error = query_records_with_source(
            &tenant(),
            &LifecycleQuery {
                findings_only: true,
                limit: Some(1),
                page_token: Some(token.clone()),
                ..LifecycleQuery::default()
            },
            vec![entity.clone()],
            "2026-07-26T12:00:00Z",
            source,
        )
        .unwrap_err();
        assert!(filter_error.to_string().contains("filters"));
        let revision_error = query_records_with_source(
            &tenant(),
            &LifecycleQuery {
                limit: Some(1),
                page_token: Some(token),
                ..LifecycleQuery::default()
            },
            vec![entity],
            "2026-07-26T12:00:00Z",
            QuerySource {
                graph_revision: 8,
                ..source
            },
        )
        .unwrap_err();
        assert!(revision_error.to_string().contains("revision"));
    }

    #[test]
    fn source_coverage_and_page_truncation_are_independent() {
        let result = query_records_with_source(
            &tenant(),
            &LifecycleQuery::default(),
            vec![projected(observation(
                LifecycleState::Active,
                "key-1",
                Some("2027-07-01T12:00:00Z"),
            ))],
            "2026-07-26T12:00:00Z",
            QuerySource {
                scanned_entities: 10_000,
                truncated: true,
                graph_revision: 9,
                graph_changed: false,
            },
        )
        .unwrap();
        assert!(!result.metadata.page_truncated);
        assert!(!result.metadata.coverage.complete);
        assert!(result.metadata.coverage.truncated);
        assert!(!result.aggregates.counts_are_exact);
        assert!(result.truncated);
    }

    #[test]
    fn graph_changed_results_are_incomplete_and_not_continuable() {
        let mut second = observation(
            LifecycleState::Active,
            "material-2",
            Some("2027-07-01T12:00:00Z"),
        );
        second.stable_locator = "second".to_owned();
        second.subject_ref.id = canonical_resource_urn(
            "tenant-a",
            second.subject_kind,
            &second.authority_id,
            &second.stable_locator,
        )
        .unwrap();
        let result = query_records_with_source(
            &tenant(),
            &LifecycleQuery {
                limit: Some(1),
                ..LifecycleQuery::default()
            },
            vec![
                projected(observation(
                    LifecycleState::Active,
                    "material-1",
                    Some("2027-07-01T12:00:00Z"),
                )),
                projected(second),
            ],
            "2026-07-26T12:00:00Z",
            QuerySource {
                scanned_entities: 2,
                graph_revision: 18,
                graph_changed: true,
                ..QuerySource::default()
            },
        )
        .unwrap();

        assert_eq!(
            result.metadata.coverage.reason,
            CoverageReason::GraphChanged
        );
        assert!(!result.metadata.coverage.complete);
        assert!(result.metadata.page_truncated);
        assert!(result.next_page_token.is_none());
        assert!(result.previous_page_token.is_none());
    }

    #[test]
    fn indexed_prepare_and_finalize_preserve_filters_cursors_and_provenance() {
        let owner = "urn:cerebro:tenant-a:team:security".to_owned();
        let locator = SubjectLocator {
            subject_kind: SubjectKind::Credential,
            authority_id: "aws/production".to_owned(),
            stable_locator: "deploy/signing".to_owned(),
        };
        let query = LifecycleQuery {
            subject_kinds: vec![SubjectKind::Credential, SubjectKind::Credential],
            states: vec![LifecycleState::Expired, LifecycleState::Expired],
            owner_urns: vec![owner.clone(), owner.clone()],
            expires_before: Some("2026-08-01T12:00:00Z".to_owned()),
            findings_only: true,
            subject_locator: Some(locator),
            limit: Some(1),
            ..LifecycleQuery::default()
        };
        let prepared =
            prepare_indexed_query(&tenant(), &query, "2026-07-26T12:00:00Z", 18).unwrap();

        assert_eq!(prepared.limit(), 1);
        assert_eq!(prepared.subject_kinds(), &[SubjectKind::Credential]);
        assert_eq!(prepared.states(), &[LifecycleState::Expired]);
        assert_eq!(prepared.owner_urns(), &[owner]);
        assert_eq!(
            prepared.expires_before_unix_ms(),
            Some(timestamp_millis_from_rfc3339("2026-08-01T12:00:00Z").unwrap())
        );
        assert!(prepared.findings_only());
        assert_eq!(
            prepared.locator_urn(),
            Some(
                canonical_resource_urn(
                    "tenant-a",
                    SubjectKind::Credential,
                    "aws/production",
                    "deploy/signing"
                )
                .unwrap()
                .as_str()
            )
        );
        assert_eq!(prepared.direction(), KeysetDirection::Forward);
        assert_eq!(prepared.cursor_subject_urn(), None);
        assert_eq!(prepared.graph_revision(), 18);
        assert_eq!(prepared.effective_as_of(), "2026-07-26T12:00:00Z");
        assert_eq!(
            prepared.effective_as_of_unix_ms(),
            timestamp_millis_from_rfc3339("2026-07-26T12:00:00Z").unwrap()
        );
        assert!(prepared.warning_cutoff_unix_ms() > prepared.effective_as_of_unix_ms());

        let mut resource = projected(observation(
            LifecycleState::Expired,
            "material-1",
            Some("2026-07-01T12:00:00Z"),
        ));
        resource
            .properties
            .insert("source_runtime_id".to_owned(), "expiry-tracker".to_owned());
        resource.properties.insert(
            "source_collection_id".to_owned(),
            "runtime-collection-1".to_owned(),
        );
        let result = finalize_indexed_query(
            &tenant(),
            &prepared,
            IndexedLifecyclePage {
                resources: vec![resource],
                aggregates: indexed_aggregates(3),
                lifecycle_entities: 8,
                oldest_observed_at: Some("2026-07-20T12:00:00Z".to_owned()),
                newest_observed_at: Some("2026-07-26T12:00:00Z".to_owned()),
                has_previous: true,
                has_next: true,
                graph_revision: 18,
                graph_changed: false,
            },
        )
        .unwrap();

        assert_eq!(result.records[0].source_runtime_id, "expiry-tracker");
        assert_eq!(
            result.records[0].source_collection_id,
            "runtime-collection-1"
        );
        assert!(result.metadata.coverage.complete);
        assert!(!result.metadata.coverage.truncated);
        assert!(result.metadata.page_truncated);
        assert!(result.truncated);
        assert_eq!(result.metadata.coverage.lifecycle_entities, 8);
        let mut backward_query = query.clone();
        backward_query.page_token = result.previous_page_token;
        let backward =
            prepare_indexed_query(&tenant(), &backward_query, "2026-07-26T12:01:00Z", 18).unwrap();
        assert_eq!(backward.direction(), KeysetDirection::Backward);
        assert_eq!(
            backward.cursor_subject_urn(),
            Some(result.records[0].observation.subject_ref.id.as_str())
        );

        let mut forward_query = query;
        forward_query.page_token = result.next_page_token;
        let forward =
            prepare_indexed_query(&tenant(), &forward_query, "2026-07-26T12:01:00Z", 18).unwrap();
        assert_eq!(forward.direction(), KeysetDirection::Forward);
    }

    #[test]
    fn indexed_prepare_rejects_unbounded_invalid_and_stale_inputs() {
        for query in [
            LifecycleQuery {
                subject_kinds: vec![SubjectKind::Credential; MAX_QUERY_FILTER_VALUES + 1],
                ..LifecycleQuery::default()
            },
            LifecycleQuery {
                states: vec![LifecycleState::Active; MAX_QUERY_FILTER_VALUES + 1],
                ..LifecycleQuery::default()
            },
            LifecycleQuery {
                owner_urns: vec![
                    "urn:cerebro:tenant-a:team:security".to_owned();
                    MAX_QUERY_FILTER_VALUES + 1
                ],
                ..LifecycleQuery::default()
            },
        ] {
            assert!(prepare_indexed_query(&tenant(), &query, "2026-07-26T12:00:00Z", 18).is_err());
        }
        for query in [
            LifecycleQuery {
                limit: Some(0),
                ..LifecycleQuery::default()
            },
            LifecycleQuery {
                expires_before: Some("not-a-time".to_owned()),
                ..LifecycleQuery::default()
            },
            LifecycleQuery {
                owner_urns: vec!["urn:cerebro:tenant-b:team:security".to_owned()],
                ..LifecycleQuery::default()
            },
            LifecycleQuery {
                subject_kinds: vec![SubjectKind::Certificate],
                subject_locator: Some(SubjectLocator {
                    subject_kind: SubjectKind::Credential,
                    authority_id: "aws/production".to_owned(),
                    stable_locator: "deploy/signing".to_owned(),
                }),
                ..LifecycleQuery::default()
            },
        ] {
            assert!(prepare_indexed_query(&tenant(), &query, "2026-07-26T12:00:00Z", 18).is_err());
        }
        assert!(
            prepare_indexed_query(&tenant(), &LifecycleQuery::default(), "not-a-time", 18).is_err()
        );

        let base = LifecycleQuery {
            limit: Some(1),
            ..LifecycleQuery::default()
        };
        let token = encode_page_token(&PageCursor {
            direction: CursorDirection::Forward,
            graph_revision: 18,
            as_of: "2026-07-26T12:00:00Z".to_owned(),
            filter_digest: query_filter_digest(&base, 1, None),
            subject_urn: canonical_resource_urn(
                "tenant-a",
                SubjectKind::Credential,
                "aws/production",
                "deploy/signing",
            )
            .unwrap(),
        });
        let with_token = LifecycleQuery {
            page_token: Some(token.clone()),
            ..base.clone()
        };
        assert!(prepare_indexed_query(&tenant(), &with_token, "2026-07-26T12:00:00Z", 19).is_err());
        let mismatched = LifecycleQuery {
            findings_only: true,
            page_token: Some(token),
            ..base
        };
        assert!(prepare_indexed_query(&tenant(), &mismatched, "2026-07-26T12:00:00Z", 18).is_err());

        for cursor_as_of in ["2026-07-26T11:40:00Z", "2026-07-26T12:01:00Z"] {
            let query = LifecycleQuery {
                limit: Some(1),
                page_token: Some(encode_page_token(&PageCursor {
                    direction: CursorDirection::Forward,
                    graph_revision: 18,
                    as_of: cursor_as_of.to_owned(),
                    filter_digest: query_filter_digest(
                        &LifecycleQuery {
                            limit: Some(1),
                            ..LifecycleQuery::default()
                        },
                        1,
                        None,
                    ),
                    subject_urn: canonical_resource_urn(
                        "tenant-a",
                        SubjectKind::Credential,
                        "aws/production",
                        "deploy/signing",
                    )
                    .unwrap(),
                })),
                ..LifecycleQuery::default()
            };
            assert!(prepare_indexed_query(&tenant(), &query, "2026-07-26T12:00:00Z", 18).is_err());
        }
    }

    #[test]
    fn indexed_finalize_rejects_invalid_pages_and_duplicate_identity() {
        let prepared = prepare_indexed_query(
            &tenant(),
            &LifecycleQuery {
                limit: Some(1),
                ..LifecycleQuery::default()
            },
            "2026-07-26T12:00:00Z",
            18,
        )
        .unwrap();
        let resource = projected(observation(
            LifecycleState::Expired,
            "material-1",
            Some("2026-07-01T12:00:00Z"),
        ));
        let page = |resources| IndexedLifecyclePage {
            resources,
            aggregates: indexed_aggregates(1),
            lifecycle_entities: 1,
            oldest_observed_at: None,
            newest_observed_at: None,
            has_previous: false,
            has_next: false,
            graph_revision: 18,
            graph_changed: false,
        };
        assert!(
            finalize_indexed_query(&tenant(), &prepared, page(vec![resource.clone(); 2])).is_err()
        );
        assert!(
            finalize_indexed_query(
                &tenant(),
                &prepared,
                page(vec![ProjectedResource {
                    agent_key: "unrelated".to_owned(),
                    label: "Unrelated".to_owned(),
                    properties: BTreeMap::new(),
                }])
            )
            .is_err()
        );

        let prepared_two = prepare_indexed_query(
            &tenant(),
            &LifecycleQuery {
                limit: Some(2),
                ..LifecycleQuery::default()
            },
            "2026-07-26T12:00:00Z",
            18,
        )
        .unwrap();
        assert!(
            finalize_indexed_query(
                &tenant(),
                &prepared_two,
                page(vec![resource.clone(), resource])
            )
            .is_err()
        );
    }

    #[test]
    fn finding_resolver_returns_only_the_matching_current_open_finding() {
        let expired = observation(
            LifecycleState::Expired,
            "material-1",
            Some("2026-07-01T12:00:00Z"),
        );
        let finding_urn = canonical_finding_urn("tenant-a", &expired.subject_ref.id).unwrap();
        let record = resolve_finding_record(
            &tenant(),
            &finding_urn,
            projected(expired.clone()),
            "2026-07-26T12:00:00Z",
            18,
        )
        .unwrap()
        .unwrap();
        assert_eq!(record.findings[0].finding_ref.id, finding_urn);

        let compliant = observation(
            LifecycleState::Active,
            "material-2",
            Some("2027-07-01T12:00:00Z"),
        );
        assert!(
            resolve_finding_record(
                &tenant(),
                &canonical_finding_urn("tenant-a", &compliant.subject_ref.id).unwrap(),
                projected(compliant.clone()),
                "2026-07-26T12:00:00Z",
                18,
            )
            .unwrap()
            .is_none()
        );
        assert!(
            resolve_finding_record(
                &tenant(),
                "urn:cerebro:tenant-a:finding:security-lifecycle:wrong",
                projected(expired),
                "2026-07-26T12:00:00Z",
                18,
            )
            .is_err()
        );
        assert!(
            resolve_finding_record(
                &tenant(),
                "urn:cerebro:tenant-b:finding:security-lifecycle:wrong",
                projected(compliant),
                "2026-07-26T12:00:00Z",
                18,
            )
            .is_err()
        );
    }

    #[test]
    fn indexed_revision_mismatch_is_truncated_and_not_continuable() {
        let resource = projected(observation(
            LifecycleState::Expired,
            "material-1",
            Some("2026-07-01T12:00:00Z"),
        ));
        let query = LifecycleQuery {
            limit: Some(1),
            ..LifecycleQuery::default()
        };
        let prepared =
            prepare_indexed_query(&tenant(), &query, "2026-07-26T12:00:00Z", 18).unwrap();
        let result = finalize_indexed_query(
            &tenant(),
            &prepared,
            IndexedLifecyclePage {
                resources: vec![resource],
                aggregates: LifecycleAggregates {
                    counts_are_exact: true,
                    matched_records: 2,
                    matched_findings: 2,
                    subject_kind_counts: vec![
                        SubjectKindCount {
                            subject_kind: SubjectKind::Credential,
                            count: 2,
                        },
                        SubjectKindCount {
                            subject_kind: SubjectKind::Certificate,
                            count: 0,
                        },
                    ],
                    state_counts: [
                        LifecycleState::Active,
                        LifecycleState::Expiring,
                        LifecycleState::Expired,
                        LifecycleState::Rotated,
                        LifecycleState::Revoked,
                        LifecycleState::Inactive,
                        LifecycleState::Unknown,
                    ]
                    .into_iter()
                    .map(|state| StateCount {
                        count: u64::from(state == LifecycleState::Expired) * 2,
                        state,
                    })
                    .collect(),
                    policy_state_counts: [
                        PolicyState::Compliant,
                        PolicyState::Expiring,
                        PolicyState::Expired,
                        PolicyState::Unknown,
                    ]
                    .into_iter()
                    .map(|policy_state| PolicyStateCount {
                        count: u64::from(policy_state == PolicyState::Expired) * 2,
                        policy_state,
                    })
                    .collect(),
                },
                lifecycle_entities: 2,
                oldest_observed_at: Some("2026-07-26T12:00:00Z".to_owned()),
                newest_observed_at: Some("2026-07-26T12:00:00Z".to_owned()),
                has_previous: true,
                has_next: true,
                graph_revision: 19,
                graph_changed: true,
            },
        )
        .unwrap();

        assert_eq!(
            result.metadata.coverage.reason,
            CoverageReason::GraphChanged
        );
        assert!(!result.metadata.coverage.complete);
        assert!(result.metadata.coverage.truncated);
        assert_eq!(result.metadata.coverage.scanned_entities, 0);
        assert!(!result.aggregates.counts_are_exact);
        assert!(result.next_page_token.is_none());
        assert!(result.previous_page_token.is_none());
    }

    #[test]
    fn aggregates_cover_the_filtered_population_not_only_the_page() {
        let mut observations = Vec::new();
        for (locator, state, revision) in [
            ("a", LifecycleState::Expired, "material-1"),
            ("b", LifecycleState::Expiring, "material-2"),
            ("c", LifecycleState::Active, "material-3"),
            ("d", LifecycleState::Active, "material-4"),
        ] {
            let mut value = observation(
                state,
                revision,
                Some(if locator == "c" {
                    "2027-07-01T12:00:00Z"
                } else {
                    "2026-07-01T12:00:00Z"
                }),
            );
            value.stable_locator = locator.to_owned();
            value.subject_ref.id = canonical_resource_urn(
                "tenant-a",
                value.subject_kind,
                &value.authority_id,
                &value.stable_locator,
            )
            .unwrap();
            observations.push(projected(value));
        }
        let result = query_records_with_source(
            &tenant(),
            &LifecycleQuery {
                findings_only: true,
                limit: Some(1),
                ..LifecycleQuery::default()
            },
            observations,
            "2026-07-26T12:00:00Z",
            QuerySource {
                scanned_entities: 4,
                graph_revision: 11,
                ..QuerySource::default()
            },
        )
        .unwrap();

        assert_eq!(result.records.len(), 1);
        assert_eq!(result.aggregates.matched_records, 3);
        assert_eq!(result.aggregates.matched_findings, 3);
        assert!(result.aggregates.counts_are_exact);
        assert!(result.metadata.page_truncated);
        assert_eq!(
            result
                .aggregates
                .state_counts
                .iter()
                .find(|count| count.state == LifecycleState::Active)
                .map(|count| count.count),
            Some(1)
        );
        assert_eq!(
            result
                .aggregates
                .policy_state_counts
                .iter()
                .find(|count| count.policy_state == PolicyState::Expired)
                .map(|count| count.count),
            Some(2)
        );
        assert_eq!(
            result.metadata.freshness.oldest_observed_at.as_deref(),
            Some("2026-07-26T12:00:00Z")
        );
    }

    #[test]
    fn subject_locator_uses_authority_and_stable_slot_not_material_revision() {
        let mut value = observation(
            LifecycleState::Active,
            "material-2026-08",
            Some("2027-07-01T12:00:00Z"),
        );
        value.stable_locator = "direct/slot".to_owned();
        value.subject_ref.id = canonical_resource_urn(
            "tenant-a",
            value.subject_kind,
            &value.authority_id,
            &value.stable_locator,
        )
        .unwrap();
        let result = query_records(
            &tenant(),
            &LifecycleQuery {
                subject_locator: Some(SubjectLocator {
                    subject_kind: SubjectKind::Credential,
                    authority_id: value.authority_id.clone(),
                    stable_locator: value.stable_locator.clone(),
                }),
                ..LifecycleQuery::default()
            },
            vec![projected(value)],
            "2026-07-26T12:00:00Z",
        )
        .unwrap();

        assert_eq!(result.records.len(), 1);
        assert_eq!(
            result.records[0]
                .observation
                .subject_ref
                .revision
                .as_deref(),
            Some("material-2026-08")
        );
    }

    #[test]
    fn protobuf_event_projects_durable_subject_and_finding() {
        let subject_urn = canonical_resource_urn(
            "tenant-a",
            SubjectKind::Credential,
            "aws/production",
            "deploy/signing",
        )
        .unwrap();
        let payload = WireObservation {
            subject_ref: Some(WireResourceRef {
                kind: "credential".to_owned(),
                id: subject_urn.clone(),
                revision: "key-1".to_owned(),
                api_path: String::new(),
                mcp_uri: String::new(),
                state: "active".to_owned(),
            }),
            subject_kind: WireSubjectKind::Credential as i32,
            provider: "aws".to_owned(),
            authority_id: "aws/production".to_owned(),
            stable_locator: "deploy/signing".to_owned(),
            display_name: "Deployment signing credential".to_owned(),
            state: WireLifecycleState::Active as i32,
            observed_at: Some(prost_types::Timestamp {
                seconds: 1_753_531_200,
                nanos: 0,
            }),
            issued_at: None,
            expires_at: Some(prost_types::Timestamp {
                seconds: 1_754_049_600,
                nanos: 0,
            }),
            rotated_at: None,
            revoked_at: None,
            owner_urn: "urn:cerebro:tenant-a:team:security".to_owned(),
            scope_refs: Vec::new(),
            evidence_claim_refs: Vec::new(),
            attributes: std::collections::HashMap::new(),
        }
        .encode_to_vec();
        let observed_at_unix_ms = 1_753_531_200_000;
        let observation =
            decode_protobuf_observation(&payload, &tenant(), observed_at_unix_ms).unwrap();
        let receipt = cerebro_organizational_model::CollectionReceipt::incremental(
            tenant(),
            cerebro_organizational_model::SourceRuntimeId::parse("expiry-tracker").unwrap(),
            cerebro_organizational_model::CollectionId::parse("event:event-1").unwrap(),
            CREDENTIAL_EVENT_KIND,
            observed_at_unix_ms,
        )
        .unwrap();
        let delta = project_observation(
            receipt,
            cerebro_organizational_model::ObservationId::parse("event-1").unwrap(),
            &observation,
        )
        .unwrap();
        assert_eq!(delta.entities().len(), 2);
        assert_eq!(delta.assertions().len(), 1);
        assert!(delta.entities().iter().any(|entity| {
            entity.properties().get("resource_urn") == Some(&subject_urn)
                && entity.properties().get("material_revision") == Some(&"key-1".to_owned())
                && entity.properties().get("source_runtime_id")
                    == Some(&"expiry-tracker".to_owned())
                && !entity.properties().contains_key("source_collection_id")
        }));
    }

    #[test]
    fn explicit_source_collection_provenance_projects_without_receipt_fallback() {
        let mut value = observation(
            LifecycleState::Expired,
            "material-1",
            Some("2026-07-01T12:00:00Z"),
        );
        value.attributes.insert(
            "source_collection_id".to_owned(),
            "runtime-collection-1".to_owned(),
        );
        let receipt = cerebro_organizational_model::CollectionReceipt::incremental(
            tenant(),
            cerebro_organizational_model::SourceRuntimeId::parse("expiry-tracker").unwrap(),
            cerebro_organizational_model::CollectionId::parse("event:observation-1").unwrap(),
            CREDENTIAL_EVENT_KIND,
            timestamp_millis_from_rfc3339("2026-07-26T12:00:00Z").unwrap(),
        )
        .unwrap();
        let delta = project_observation(
            receipt,
            cerebro_organizational_model::ObservationId::parse("observation-1").unwrap(),
            &value,
        )
        .unwrap();

        assert_eq!(delta.entities().len(), 2);
        for entity in delta.entities() {
            assert_eq!(
                entity.properties().get("source_runtime_id"),
                Some(&"expiry-tracker".to_owned())
            );
            assert_eq!(
                entity.properties().get("source_collection_id"),
                Some(&"runtime-collection-1".to_owned())
            );
            assert_ne!(
                entity.properties().get("source_collection_id"),
                Some(&"event:observation-1".to_owned())
            );
        }
    }

    #[test]
    fn indexed_public_helpers_cover_supported_states_and_time_bounds() {
        let instant = "2026-07-26T12:00:00Z";
        let millis = timestamp_millis_from_rfc3339(instant).unwrap();
        assert_eq!(rfc3339_from_timestamp_millis(millis).unwrap(), instant);
        assert!(timestamp_millis_from_rfc3339("not-a-time").is_err());
        assert!(rfc3339_from_timestamp_millis(i64::MAX).is_err());

        for (state, name) in [
            (LifecycleState::Active, "active"),
            (LifecycleState::Expiring, "expiring"),
            (LifecycleState::Expired, "expired"),
            (LifecycleState::Rotated, "rotated"),
            (LifecycleState::Revoked, "revoked"),
            (LifecycleState::Inactive, "inactive"),
            (LifecycleState::Unknown, "unknown"),
        ] {
            assert_eq!(lifecycle_state_name(state), name);
            assert_eq!(parse_state(name), Some(state));
        }
        assert_eq!(parse_state("unsupported"), None);
        assert_eq!(
            parse_subject_kind("certificate"),
            Some(SubjectKind::Certificate)
        );
        assert_eq!(parse_subject_kind("unsupported"), None);
    }
}
