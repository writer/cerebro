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

pub const CREDENTIAL_EVENT_KIND: &str = "security.credential.lifecycle";
pub const CERTIFICATE_EVENT_KIND: &str = "security.certificate.lifecycle";
pub const CREDENTIAL_SCHEMA_REF: &str = "cerebro/security/credential-lifecycle/v1";
pub const CERTIFICATE_SCHEMA_REF: &str = "cerebro/security/certificate-lifecycle/v1";
pub const EXPIRY_POLICY_ID: &str = "security.lifecycle.expiry";
pub const EXPIRY_POLICY_VERSION: &str = "1";
pub const DEFAULT_WARNING_WINDOW_DAYS: u32 = 30;
pub const DEFAULT_QUERY_LIMIT: usize = 100;
pub const MAX_QUERY_LIMIT: usize = 500;
const MAX_CURSOR_AGE: Duration = Duration::minutes(15);
const MAX_CURSOR_SUBJECT_URN_BYTES: usize = 2_048;
const MAX_PAGE_TOKEN_CHARS: usize = 4_608;
const MAX_QUERY_FILTER_VALUES: usize = 100;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum WireSubjectKind {
    Unspecified = 0,
    Credential = 1,
    Certificate = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum WireLifecycleState {
    Unspecified = 0,
    Active = 1,
    Expiring = 2,
    Expired = 3,
    Rotated = 4,
    Revoked = 5,
    Inactive = 6,
    Unknown = 7,
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    Invalid(&'static str),
    InvalidValue(String),
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Credential,
    Certificate,
}

impl SubjectKind {
    pub fn event_contract(self) -> (&'static str, &'static str) {
        match self {
            Self::Credential => (CREDENTIAL_EVENT_KIND, CREDENTIAL_SCHEMA_REF),
            Self::Certificate => (CERTIFICATE_EVENT_KIND, CERTIFICATE_SCHEMA_REF),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Certificate => "certificate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Active,
    Expiring,
    Expired,
    Rotated,
    Revoked,
    Inactive,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRef {
    pub kind: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub subject_ref: ResourceRef,
    pub subject_kind: SubjectKind,
    pub provider: String,
    pub authority_id: String,
    pub stable_locator: String,
    pub display_name: String,
    pub state: LifecycleState,
    pub observed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_urn: Option<String>,
    #[serde(default)]
    pub scope_refs: Vec<ResourceRef>,
    #[serde(default)]
    pub evidence_claim_refs: Vec<ResourceRef>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedResource {
    pub agent_key: String,
    pub label: String,
    pub properties: BTreeMap<String, String>,
}

impl Observation {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyEvaluation {
    pub policy_id: &'static str,
    pub policy_version: &'static str,
    pub subject_ref: ResourceRef,
    pub state: &'static str,
    pub warning_window_days: u32,
    pub seconds_until_expiry: Option<i64>,
    pub evaluated_at: String,
    pub evidence_claim_refs: Vec<ResourceRef>,
}

impl PolicyEvaluation {
    pub fn has_finding(&self) -> bool {
        matches!(self.state, "expiring" | "expired")
    }
}

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FindingBinding {
    pub finding_ref: ResourceRef,
    pub subject_ref: ResourceRef,
    pub finding_kind: String,
    pub status: String,
    pub evidence_claim_refs: Vec<ResourceRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionRoute {
    pub finding_ref: ResourceRef,
    pub target_ref: ResourceRef,
    pub action_type: String,
    pub approval_required: bool,
    pub action_intent_ref: ResourceRef,
    pub dispatch_ref: ResourceRef,
    pub verification_ref: ResourceRef,
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationExpectation {
    pub tenant_id: TenantId,
    pub finding_ref: ResourceRef,
    pub remediation_outcome_ref: ResourceRef,
    pub subject_ref: ResourceRef,
    pub source_runtime_ref: ResourceRef,
    pub dispatched_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerificationBinding {
    pub finding_ref: ResourceRef,
    pub remediation_outcome_ref: ResourceRef,
    pub observation_event_ref: ResourceRef,
    pub source_runtime_ref: ResourceRef,
    pub result: &'static str,
    pub source_complete: bool,
    pub source_truncated: bool,
    pub observed_at: String,
    pub evidence_claim_refs: Vec<ResourceRef>,
}

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

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct LifecycleQuery {
    #[serde(default)]
    pub subject_kinds: Vec<SubjectKind>,
    #[serde(default)]
    pub states: Vec<LifecycleState>,
    #[serde(default)]
    pub owner_urns: Vec<String>,
    #[serde(default)]
    pub expires_before: Option<String>,
    #[serde(default)]
    pub findings_only: bool,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub page_token: Option<String>,
    #[serde(default)]
    pub subject_locator: Option<SubjectLocator>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SubjectLocator {
    pub subject_kind: SubjectKind,
    pub authority_id: String,
    pub stable_locator: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LifecycleRecord {
    pub observation: Observation,
    pub policy_evaluations: Vec<PolicyEvaluation>,
    pub findings: Vec<FindingBinding>,
    pub action_routes: Vec<ActionRoute>,
    pub projected_at: String,
    pub source_runtime_id: String,
    pub source_collection_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryResult {
    pub records: Vec<LifecycleRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_page_token: Option<String>,
    pub truncated: bool,
    pub as_of: String,
    pub aggregates: LifecycleAggregates,
    pub metadata: QueryMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SubjectKindCount {
    pub subject_kind: SubjectKind,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StateCount {
    pub state: LifecycleState,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    Compliant,
    Expiring,
    Expired,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyStateCount {
    pub policy_state: PolicyState,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LifecycleAggregates {
    pub counts_are_exact: bool,
    pub matched_records: u64,
    pub matched_findings: u64,
    pub subject_kind_counts: Vec<SubjectKindCount>,
    pub state_counts: Vec<StateCount>,
    pub policy_state_counts: Vec<PolicyStateCount>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageReason {
    Complete,
    ScanLimit,
    GraphChanged,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryCoverage {
    pub complete: bool,
    pub truncated: bool,
    pub scanned_entities: u64,
    pub lifecycle_entities: u64,
    pub graph_revision: u64,
    pub reason: CoverageReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryFreshness {
    pub as_of: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_observed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_observed_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryMetadata {
    pub coverage: QueryCoverage,
    pub freshness: QueryFreshness,
    pub page_truncated: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuerySource {
    pub scanned_entities: usize,
    pub truncated: bool,
    pub graph_revision: u64,
    pub graph_changed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeysetDirection {
    Forward,
    Backward,
}

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
    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn subject_kinds(&self) -> &[SubjectKind] {
        &self.subject_kinds
    }

    pub fn states(&self) -> &[LifecycleState] {
        &self.states
    }

    pub fn owner_urns(&self) -> &[String] {
        &self.owner_urns
    }

    pub fn expires_before_unix_ms(&self) -> Option<i64> {
        self.expires_before_unix_ms
    }

    pub fn findings_only(&self) -> bool {
        self.findings_only
    }

    pub fn locator_urn(&self) -> Option<&str> {
        self.locator_urn.as_deref()
    }

    pub fn direction(&self) -> KeysetDirection {
        self.direction
    }

    pub fn cursor_subject_urn(&self) -> Option<&str> {
        self.cursor_subject_urn.as_deref()
    }

    pub fn graph_revision(&self) -> u64 {
        self.graph_revision
    }

    pub fn effective_as_of(&self) -> &str {
        &self.effective_as_of
    }

    pub fn effective_as_of_unix_ms(&self) -> i64 {
        self.effective_as_of_unix_ms
    }

    pub fn warning_cutoff_unix_ms(&self) -> i64 {
        self.warning_cutoff_unix_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedLifecyclePage {
    pub resources: Vec<ProjectedResource>,
    pub aggregates: LifecycleAggregates,
    pub lifecycle_entities: u64,
    pub oldest_observed_at: Option<String>,
    pub newest_observed_at: Option<String>,
    pub has_previous: bool,
    pub has_next: bool,
    pub graph_revision: u64,
    pub graph_changed: bool,
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct Candidate {
    observation: Observation,
    evaluation: PolicyEvaluation,
    source_runtime_id: String,
    source_collection_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CursorDirection {
    Forward,
    Backward,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PageCursor {
    direction: CursorDirection,
    graph_revision: u64,
    as_of: String,
    filter_digest: String,
    subject_urn: String,
}

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

fn canonical_filter_values(mut values: Vec<&str>) -> String {
    values.sort_unstable();
    values.dedup();
    values.join(",")
}

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

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

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

fn subject_kind_index(kind: SubjectKind) -> usize {
    match kind {
        SubjectKind::Credential => 0,
        SubjectKind::Certificate => 1,
    }
}

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

fn policy_state(evaluation: &PolicyEvaluation) -> Result<PolicyState, LifecycleError> {
    match evaluation.state {
        "compliant" => Ok(PolicyState::Compliant),
        "expiring" => Ok(PolicyState::Expiring),
        "expired" => Ok(PolicyState::Expired),
        "unknown" => Ok(PolicyState::Unknown),
        _ => Err(LifecycleError::Invalid("policy evaluation state")),
    }
}

fn policy_state_index(state: PolicyState) -> usize {
    match state {
        PolicyState::Compliant => 0,
        PolicyState::Expiring => 1,
        PolicyState::Expired => 2,
        PolicyState::Unknown => 3,
    }
}

fn format_optional_time(value: Option<OffsetDateTime>) -> Result<Option<String>, LifecycleError> {
    value
        .map(|value| {
            value
                .format(&Rfc3339)
                .map_err(|_| LifecycleError::Invalid("observed_at"))
        })
        .transpose()
}

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

pub fn canonical_finding_urn(tenant_id: &str, finding_id: &str) -> Result<String, LifecycleError> {
    canonical_single_id_urn(tenant_id, "finding", finding_id)
}

pub fn canonical_remediation_outcome_urn(
    tenant_id: &str,
    outcome_id: &str,
) -> Result<String, LifecycleError> {
    canonical_single_id_urn(tenant_id, "remediation_outcome", outcome_id)
}

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

fn require_tenant_urn(tenant_id: &str, value: &str) -> Result<(), LifecycleError> {
    let expected = format!("urn:cerebro:{}:", encode_segment(tenant_id));
    if !value.starts_with(&expected) || value.len() == expected.len() {
        return Err(LifecycleError::Invalid("tenant-scoped URN"));
    }
    Ok(())
}

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

fn parse_time(value: &str, field: &'static str) -> Result<OffsetDateTime, LifecycleError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| LifecycleError::Invalid(field))
}

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

pub fn timestamp_millis_from_rfc3339(value: &str) -> Result<i64, LifecycleError> {
    let timestamp = parse_time(value, "timestamp")?;
    i64::try_from(timestamp.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| LifecycleError::Invalid("timestamp"))
}

pub fn rfc3339_from_timestamp_millis(value: i64) -> Result<String, LifecycleError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(value).saturating_mul(1_000_000))
        .map_err(|_| LifecycleError::Invalid("timestamp"))?
        .format(&Rfc3339)
        .map_err(|_| LifecycleError::Invalid("timestamp"))
}

fn resource_ref(value: WireResourceRef) -> ResourceRef {
    ResourceRef {
        kind: value.kind,
        id: value.id,
        revision: (!value.revision.trim().is_empty()).then_some(value.revision),
        state: (!value.state.trim().is_empty()).then_some(value.state),
    }
}

fn stable_entity_id(prefix: &str, value: &str) -> Result<EntityId, LifecycleError> {
    let digest = Sha256::digest(value.as_bytes());
    let suffix = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    EntityId::parse(format!("{prefix}:{suffix}")).map_err(model_error)
}

fn model_error(error: impl fmt::Display) -> LifecycleError {
    LifecycleError::InvalidValue(error.to_string())
}

fn parse_subject_kind(value: &str) -> Option<SubjectKind> {
    match value.trim() {
        "credential" => Some(SubjectKind::Credential),
        "certificate" => Some(SubjectKind::Certificate),
        _ => None,
    }
}

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
}
