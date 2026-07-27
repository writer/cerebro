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
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const CREDENTIAL_EVENT_KIND: &str = "security.credential.lifecycle";
pub const CERTIFICATE_EVENT_KIND: &str = "security.certificate.lifecycle";
pub const CREDENTIAL_SCHEMA_REF: &str = "cerebro/security/credential-lifecycle/v1";
pub const CERTIFICATE_SCHEMA_REF: &str = "cerebro/security/certificate-lifecycle/v1";
pub const EXPIRY_POLICY_ID: &str = "security.lifecycle.expiry";
pub const EXPIRY_POLICY_VERSION: &str = "1";
pub const DEFAULT_WARNING_WINDOW_DAYS: u32 = 30;
pub const DEFAULT_QUERY_LIMIT: usize = 100;
pub const MAX_QUERY_LIMIT: usize = 500;

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

    fn as_str(self) -> &'static str {
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
            scope_refs: Vec::new(),
            evidence_claim_refs: Vec::new(),
            attributes: BTreeMap::new(),
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
    for (key, value) in projection_properties(observation) {
        subject = subject.with_property(key, value).map_err(model_error)?;
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
        let finding = Entity::canonical(
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
        .map_err(model_error)?;
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

fn projection_properties(observation: &Observation) -> BTreeMap<String, String> {
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
    properties
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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LifecycleRecord {
    pub observation: Observation,
    pub policy_evaluations: Vec<PolicyEvaluation>,
    pub findings: Vec<FindingBinding>,
    pub action_routes: Vec<ActionRoute>,
    pub projected_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryResult {
    pub records: Vec<LifecycleRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    pub truncated: bool,
    pub as_of: String,
}

pub fn query_records(
    tenant_id: &TenantId,
    query: &LifecycleQuery,
    entities: Vec<ProjectedResource>,
    as_of: &str,
) -> Result<QueryResult, LifecycleError> {
    let limit = query.limit.unwrap_or(DEFAULT_QUERY_LIMIT);
    if limit == 0 || limit > MAX_QUERY_LIMIT {
        return Err(LifecycleError::InvalidValue(format!(
            "limit must be between 1 and {MAX_QUERY_LIMIT}"
        )));
    }
    parse_time(as_of, "as_of")?;
    if let Some(cutoff) = query.expires_before.as_deref() {
        parse_time(cutoff, "expires_before")?;
    }
    for owner in &query.owner_urns {
        require_tenant_urn(tenant_id.as_str(), owner)?;
    }
    let page_anchor = query
        .page_token
        .as_deref()
        .map(decode_page_token)
        .transpose()?;
    let mut records = Vec::new();
    for entity in entities {
        let Some(observation) = Observation::from_graph(entity)? else {
            continue;
        };
        observation.validate(tenant_id)?;
        if (!query.subject_kinds.is_empty()
            && !query.subject_kinds.contains(&observation.subject_kind))
            || (!query.states.is_empty() && !query.states.contains(&observation.state))
            || (!query.owner_urns.is_empty()
                && observation
                    .owner_urn
                    .as_ref()
                    .is_none_or(|owner| !query.owner_urns.contains(owner)))
            || query.expires_before.as_deref().is_some_and(|cutoff| {
                let cutoff = parse_time(cutoff, "expires_before").expect("query validated");
                observation
                    .expires_at
                    .as_deref()
                    .and_then(|value| parse_time(value, "expires_at").ok())
                    .is_none_or(|expiry| expiry >= cutoff)
            })
        {
            continue;
        }
        let evaluation = evaluate(&observation, as_of, DEFAULT_WARNING_WINDOW_DAYS)?;
        if query.findings_only && !evaluation.has_finding() {
            continue;
        }
        let mut findings = Vec::new();
        let mut action_routes = Vec::new();
        if evaluation.has_finding() {
            let finding_ref = ResourceRef {
                kind: "finding".to_owned(),
                id: canonical_finding_urn(tenant_id.as_str(), &observation.subject_ref.id)?,
                revision: observation.subject_ref.revision.clone(),
                state: Some("open".to_owned()),
            };
            findings.push(FindingBinding {
                finding_ref: finding_ref.clone(),
                subject_ref: observation.subject_ref.clone(),
                finding_kind: format!("{}_expiry", observation.subject_kind.as_str()),
                status: "open".to_owned(),
                evidence_claim_refs: observation.evidence_claim_refs.clone(),
            });
            action_routes.push(action_route(tenant_id, finding_ref, &observation, true)?);
        }
        records.push(LifecycleRecord {
            observation,
            policy_evaluations: vec![evaluation],
            findings,
            action_routes,
            projected_at: as_of.to_owned(),
        });
    }
    records.sort_by(|left, right| {
        left.observation
            .subject_ref
            .id
            .cmp(&right.observation.subject_ref.id)
            .then_with(|| {
                left.observation
                    .subject_ref
                    .revision
                    .cmp(&right.observation.subject_ref.revision)
            })
    });
    if let Some((anchor_id, anchor_revision)) = page_anchor.as_ref() {
        records.retain(|record| {
            (
                record.observation.subject_ref.id.as_str(),
                record.observation.subject_ref.revision.as_deref(),
            ) > (anchor_id.as_str(), anchor_revision.as_deref())
        });
    }
    let truncated = records.len() > limit;
    records.truncate(limit);
    let next_page_token = truncated.then(|| records.last()).flatten().map(|record| {
        encode_page_token(
            &record.observation.subject_ref.id,
            record.observation.subject_ref.revision.as_deref(),
        )
    });
    Ok(QueryResult {
        records,
        next_page_token,
        truncated,
        as_of: as_of.to_owned(),
    })
}

fn encode_page_token(subject_urn: &str, revision: Option<&str>) -> String {
    let raw = format!("{subject_urn}\0{}", revision.unwrap_or_default());
    let mut encoded = String::with_capacity(3 + raw.len() * 2);
    encoded.push_str("v1.");
    for byte in raw.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn decode_page_token(token: &str) -> Result<(String, Option<String>), LifecycleError> {
    let encoded = token
        .strip_prefix("v1.")
        .filter(|encoded| !encoded.is_empty() && encoded.len() % 2 == 0)
        .ok_or_else(|| LifecycleError::InvalidValue("invalid page_token".to_owned()))?;
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let value = std::str::from_utf8(pair)
                .ok()
                .and_then(|value| u8::from_str_radix(value, 16).ok());
            value.ok_or_else(|| LifecycleError::InvalidValue("invalid page_token".to_owned()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let raw = String::from_utf8(bytes)
        .map_err(|_| LifecycleError::InvalidValue("invalid page_token".to_owned()))?;
    let (subject_urn, revision) = raw
        .split_once('\0')
        .filter(|(subject_urn, _)| !subject_urn.is_empty())
        .ok_or_else(|| LifecycleError::InvalidValue("invalid page_token".to_owned()))?;
    Ok((
        subject_urn.to_owned(),
        (!revision.is_empty()).then(|| revision.to_owned()),
    ))
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
    Ok(format!(
        "urn:cerebro:{}:{}:{}:{}",
        encode_segment(tenant_id),
        kind.as_str(),
        encode_segment(authority_id),
        encode_segment(stable_locator)
    ))
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

fn timestamp_millis_from_rfc3339(value: &str) -> Result<i64, LifecycleError> {
    let timestamp = parse_time(value, "timestamp")?;
    i64::try_from(timestamp.unix_timestamp_nanos() / 1_000_000)
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
            properties: projection_properties(&observation),
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
        let token = encode_page_token(subject, Some("key-2026-07"));

        assert_ne!(token, subject);
        assert_eq!(
            decode_page_token(&token).unwrap(),
            (subject.to_owned(), Some("key-2026-07".to_owned()))
        );
        assert!(decode_page_token("v1.not-hex").is_err());
    }

    #[test]
    fn bounded_query_filters_and_resumes_with_a_composite_cursor() {
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

        let second_page = query_records(
            &tenant(),
            &LifecycleQuery {
                states: vec![LifecycleState::Expired],
                expires_before: Some("2026-07-15T12:00:00Z".to_owned()),
                page_token: first_page.next_page_token,
                ..LifecycleQuery::default()
            },
            entities,
            "2026-07-26T12:00:00Z",
        )
        .unwrap();
        assert!(!second_page.truncated);
        assert_eq!(second_page.records.len(), 1);
        assert_eq!(
            second_page.records[0].observation.state,
            LifecycleState::Expired
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
        }));
    }
}
