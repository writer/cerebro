//! Decoding and projection helpers for committed source append-log events.
//!
//! The decoder authenticates the envelope shape before exposing a source
//! event, preserves portable lifecycle payloads as protobuf bytes, and derives
//! deterministic digests and incremental collection identities for storage.

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
};

use cerebro_organizational_model::{
    CollectionId, CollectionReceipt, ObservationId, SourceRuntimeId, TenantId,
};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};

use crate::{CollectedBatch, CollectedScope, SourceRecord};

const SOURCE_RUNTIME_ID_ATTRIBUTE: &str = "source_runtime_id";
const SOURCE_COLLECTION_ID_ATTRIBUTE: &str = "source_collection_id";
const CREDENTIAL_EVENT_KIND: &str = "security.credential.lifecycle";
const CERTIFICATE_EVENT_KIND: &str = "security.certificate.lifecycle";
const CREDENTIAL_SCHEMA_REF: &str = "cerebro/security/credential-lifecycle/v1";
const CERTIFICATE_SCHEMA_REF: &str = "cerebro/security/certificate-lifecycle/v1";
const OKTA_THREAT_INSIGHT_KIND: &str = "okta.threat_insight";
const OKTA_THREAT_INSIGHT_SCHEMA_REF: &str = "okta/threat_insight/v1";
const LEGACY_OKTA_THREAT_INSIGHT_PREFIX: &str = "okta-threat-insight-";
const CURRENT_OKTA_THREAT_INSIGHT_PREFIX: &str = "okta-threat-insight-sha256-";
const COMPATIBILITY_OBSERVATION_ID_PREFIX: &str = "compat:v1:";
const SENTINELONE_APPLICATION_KIND: &str = "sentinelone.application_inventory";
const SENTINELONE_APPLICATION_SCHEMA_REF: &str = "sentinelone/application_inventory/v1";
const SENTINELONE_APPLICATION_EVENT_ID_PREFIX: &str = "sentinelone-application-";
const SENTINELONE_APPLICATION_COMPATIBILITY_DOMAIN: &str =
    "cerebro.compat-observation-id.sentinelone-application/v1";
const MAX_SENTINELONE_APPLICATION_EVENT_ID_BYTES: usize = 256;
const MAX_SENTINELONE_APPLICATION_COMPONENT_BYTES: usize = 256;

#[derive(Clone, PartialEq, Message)]
struct CommittedSourceWire {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, tag = "2")]
    tenant_id: String,
    #[prost(string, tag = "3")]
    source_id: String,
    #[prost(string, tag = "4")]
    kind: String,
    #[prost(message, optional, tag = "5")]
    occurred_at: Option<Timestamp>,
    #[prost(string, tag = "6")]
    schema_ref: String,
    #[prost(bytes = "vec", tag = "7")]
    payload: Vec<u8>,
    #[prost(map = "string, string", tag = "8")]
    attributes: HashMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A committed append-log envelope could not cross the source-runtime boundary.
pub enum AppendLogDecodeError {
    /// The bytes are not a valid committed-source protobuf message.
    Protobuf(String),
    /// A required field or cross-field invariant is absent.
    Missing(&'static str),
    /// The event timestamp is invalid or outside the supported representation.
    InvalidTimestamp,
    /// A catalog event payload is not valid JSON.
    InvalidPayload(String),
    /// A decoded identifier violates an organizational-model invariant.
    InvalidModel(String),
}

impl fmt::Display for AppendLogDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protobuf(message) => write!(formatter, "decode append-log protobuf: {message}"),
            Self::Missing(field) => write!(formatter, "source event is missing {field}"),
            Self::InvalidTimestamp => {
                formatter.write_str("source event occurrence time is invalid")
            }
            Self::InvalidPayload(message) => {
                write!(
                    formatter,
                    "source event payload is not valid JSON: {message}"
                )
            }
            Self::InvalidModel(message) => {
                write!(
                    formatter,
                    "source event violates the graph model: {message}"
                )
            }
        }
    }
}

impl Error for AppendLogDecodeError {}

/// A source event that came from the canonical append-log protobuf envelope.
///
/// Callers cannot construct this value directly. Tenant, runtime, observation,
/// family, timestamp, and payload validation happen before it crosses the Rust
/// graph boundary. Catalog source events carry JSON; portable security
/// lifecycle events retain their protobuf payload for the sealed lifecycle
/// projector.
#[derive(Clone, Debug, PartialEq)]
pub struct CommittedSourceEvent {
    tenant_id: TenantId,
    source_runtime_id: SourceRuntimeId,
    observation_id: ObservationId,
    source_id: String,
    family_id: String,
    event_kind: String,
    schema_ref: String,
    observed_at_unix_ms: i64,
    attributes: BTreeMap<String, String>,
    payload: serde_json::Value,
    raw_payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
/// Validated fields for constructing a committed source event without protobuf.
pub struct CommittedSourceInput {
    /// Tenant that owns the source observation.
    pub tenant_id: TenantId,
    /// Concrete connector runtime that produced the observation.
    pub source_runtime_id: SourceRuntimeId,
    /// Globally stable identifier for this observation.
    pub observation_id: ObservationId,
    /// Catalog source identifier, such as `github` or `okta`.
    pub source_id: String,
    /// Source-owned family identifier within the catalog.
    pub family_id: String,
    /// Fully qualified event kind, normally `source.family`.
    pub event_kind: String,
    /// Schema that gives the payload its portable meaning.
    pub schema_ref: String,
    /// Authoritative observation time as Unix milliseconds.
    pub observed_at_unix_ms: i64,
    /// Bounded envelope metadata carried into the source record.
    pub attributes: BTreeMap<String, String>,
    /// Decoded catalog payload used by ordinary graph mappers.
    pub payload: serde_json::Value,
}

impl CommittedSourceEvent {
    /// Validate already decoded fields and construct a committed event.
    pub fn from_input(input: CommittedSourceInput) -> Result<Self, AppendLogDecodeError> {
        let source_id = required(&input.source_id, "source_id")?.to_owned();
        let family_id = required(&input.family_id, "family_id")?.to_owned();
        let event_kind = required(&input.event_kind, "event_kind")?.to_owned();
        if event_kind != format!("{source_id}.{family_id}") {
            return Err(AppendLogDecodeError::Missing(
                "a source-owned kind in source.family form",
            ));
        }
        if input.observed_at_unix_ms <= 0 {
            return Err(AppendLogDecodeError::InvalidTimestamp);
        }
        Ok(Self {
            tenant_id: input.tenant_id,
            source_runtime_id: input.source_runtime_id,
            observation_id: input.observation_id,
            source_id,
            family_id,
            event_kind,
            schema_ref: input.schema_ref.trim().to_owned(),
            observed_at_unix_ms: input.observed_at_unix_ms,
            attributes: input.attributes,
            payload: input.payload,
            raw_payload: Vec::new(),
        })
    }

    /// Decode a canonical append-log envelope.
    ///
    /// `Ok(None)` means the envelope is not a connector source event. Once an
    /// envelope identifies a source, malformed source data is an error rather
    /// than something the consumer may silently skip.
    pub fn decode(payload: &[u8]) -> Result<Option<Self>, AppendLogDecodeError> {
        let wire = CommittedSourceWire::decode(payload)
            .map_err(|error| AppendLogDecodeError::Protobuf(error.to_string()))?;
        let source_id = wire.source_id.trim().to_owned();
        if source_id.is_empty() {
            return Ok(None);
        }
        let kind = wire.kind.trim();
        let source_prefix = format!("{source_id}.");
        let portable_lifecycle = match kind {
            CREDENTIAL_EVENT_KIND => wire.schema_ref.trim() == CREDENTIAL_SCHEMA_REF,
            CERTIFICATE_EVENT_KIND => wire.schema_ref.trim() == CERTIFICATE_SCHEMA_REF,
            _ => false,
        };
        if !portable_lifecycle
            && (!kind.starts_with(&source_prefix) || kind.len() == source_prefix.len())
        {
            return Err(AppendLogDecodeError::Missing(
                "a source-owned kind in source.family form",
            ));
        }
        if matches!(kind, CREDENTIAL_EVENT_KIND | CERTIFICATE_EVENT_KIND) && !portable_lifecycle {
            return Err(AppendLogDecodeError::Missing(
                "the matching security lifecycle schema_ref",
            ));
        }
        let tenant = required(&wire.tenant_id, "tenant_id")?;
        let runtime = wire
            .attributes
            .get(SOURCE_RUNTIME_ID_ATTRIBUTE)
            .map(String::as_str)
            .ok_or(AppendLogDecodeError::Missing("source_runtime_id"))?;
        let event_id = required(&wire.id, "event_id")?;
        let occurred_at = wire
            .occurred_at
            .ok_or(AppendLogDecodeError::Missing("occurred_at"))?;
        let observed_at_unix_ms = timestamp_millis(occurred_at)?;
        let payload = if portable_lifecycle || wire.payload.is_empty() {
            serde_json::Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_slice(&wire.payload)
                .map_err(|error| AppendLogDecodeError::InvalidPayload(error.to_string()))?
        };
        let tenant_id = TenantId::parse(tenant).map_err(model_error)?;
        let source_runtime_id =
            SourceRuntimeId::parse(required(runtime, "source_runtime_id")?).map_err(model_error)?;
        let observation_id = decode_observation_id(
            event_id,
            &tenant_id,
            &source_id,
            kind,
            wire.schema_ref.trim(),
            observed_at_unix_ms,
            &wire.attributes,
            &payload,
        )?;
        Ok(Some(Self {
            tenant_id,
            source_runtime_id,
            observation_id,
            source_id,
            family_id: if portable_lifecycle {
                kind.to_owned()
            } else {
                kind[source_prefix.len()..].to_owned()
            },
            event_kind: kind.to_owned(),
            schema_ref: wire.schema_ref.trim().to_owned(),
            observed_at_unix_ms,
            attributes: wire.attributes.into_iter().collect(),
            payload,
            raw_payload: wire.payload,
        }))
    }

    /// Return the tenant that owns this observation.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Return the connector runtime that produced this observation.
    pub fn source_runtime_id(&self) -> &SourceRuntimeId {
        &self.source_runtime_id
    }

    /// Return the stable observation identifier from the append log.
    pub fn observation_id(&self) -> &ObservationId {
        &self.observation_id
    }

    /// Return the catalog source identifier.
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Return the source-owned family or portable lifecycle event kind.
    pub fn family_id(&self) -> &str {
        &self.family_id
    }

    /// Return the fully qualified event kind from the envelope.
    pub fn event_kind(&self) -> &str {
        &self.event_kind
    }

    /// Return the payload schema reference supplied by the producer.
    pub fn schema_ref(&self) -> &str {
        &self.schema_ref
    }

    /// Return the authoritative observation time as Unix milliseconds.
    pub fn observed_at_unix_ms(&self) -> i64 {
        self.observed_at_unix_ms
    }

    /// Return the sorted source-event attributes.
    pub fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }

    /// Return the decoded JSON payload used by catalog mappers.
    pub fn payload(&self) -> &serde_json::Value {
        &self.payload
    }

    /// Hash all immutable identity, time, metadata, and canonical payload fields.
    ///
    /// Length-prefixing each field prevents concatenation ambiguity. The
    /// resulting lowercase SHA-256 digest is stable across map insertion order.
    /// Runtime and collection IDs are delivery provenance: materialization adds
    /// them after a source chooses its immutable observation ID, and later
    /// redelivery can legitimately use a different runtime or collection.
    pub fn record_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, self.tenant_id.as_str().as_bytes());
        hash_field(&mut hasher, self.observation_id.as_str().as_bytes());
        hash_field(&mut hasher, self.source_id.as_bytes());
        hash_field(&mut hasher, self.family_id.as_bytes());
        hash_field(&mut hasher, self.event_kind.as_bytes());
        hash_field(&mut hasher, self.schema_ref.as_bytes());
        hash_field(&mut hasher, self.observed_at_unix_ms.to_string().as_bytes());
        for (key, value) in &self.attributes {
            if matches!(
                key.as_str(),
                SOURCE_RUNTIME_ID_ATTRIBUTE | SOURCE_COLLECTION_ID_ATTRIBUTE
            ) {
                continue;
            }
            hash_field(&mut hasher, key.as_bytes());
            hash_field(&mut hasher, value.as_bytes());
        }
        let payload = self.canonical_payload_bytes();
        hash_field(&mut hasher, &payload);
        finish_digest(hasher)
    }

    /// Hash only the sorted event attributes.
    pub fn attributes_digest(&self) -> String {
        let mut hasher = Sha256::new();
        for (key, value) in &self.attributes {
            hash_field(&mut hasher, key.as_bytes());
            hash_field(&mut hasher, value.as_bytes());
        }
        finish_digest(hasher)
    }

    /// Hash only the canonical JSON payload.
    pub fn payload_digest(&self) -> String {
        let mut hasher = Sha256::new();
        let payload = self.canonical_payload_bytes();
        hash_field(&mut hasher, &payload);
        finish_digest(hasher)
    }

    /// Return the original protobuf payload bytes.
    ///
    /// Ordinary catalog events expose their JSON through [`Self::payload`];
    /// portable lifecycle projectors consume these preserved bytes instead.
    pub fn raw_payload(&self) -> &[u8] {
        &self.raw_payload
    }

    fn canonical_payload_bytes(&self) -> Vec<u8> {
        canonical_event_payload_bytes(
            &self.source_id,
            &self.event_kind,
            &self.schema_ref,
            &self.payload,
        )
    }

    /// Return whether this event is an accepted portable security lifecycle event.
    pub fn is_portable_security_lifecycle(&self) -> bool {
        matches!(
            (self.event_kind.as_str(), self.schema_ref.as_str()),
            (CREDENTIAL_EVENT_KIND, CREDENTIAL_SCHEMA_REF)
                | (CERTIFICATE_EVENT_KIND, CERTIFICATE_SCHEMA_REF)
        )
    }

    /// Derive the incremental collection identity for this observation.
    pub fn collection_id(&self) -> Result<CollectionId, AppendLogDecodeError> {
        CollectionId::parse(format!("event:{}", self.observation_id)).map_err(model_error)
    }

    /// Convert this event into a one-record, non-authoritative collection batch.
    ///
    /// Provider kind and ID are supplied by the family-specific caller because
    /// the generic append-log envelope does not own that interpretation.
    pub fn into_batch(
        self,
        provider_kind: String,
        provider_id: String,
    ) -> Result<CollectedBatch, AppendLogDecodeError> {
        let collection_id = self.collection_id()?;
        let scope = CollectionReceipt::incremental(
            self.tenant_id,
            self.source_runtime_id,
            collection_id,
            format!("{}.{}", self.source_id, self.family_id),
            self.observed_at_unix_ms,
        )
        .map_err(model_error)?;
        Ok(CollectedBatch {
            scope: CollectedScope::NonAuthoritative(scope),
            records: vec![SourceRecord {
                observation_id: self.observation_id,
                family: self.family_id,
                provider_kind,
                provider_id,
                fields: self.attributes,
                payload: self.payload,
            }],
            next_cursor: None,
        })
    }
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(value.len().to_be_bytes());
    hasher.update(value);
}

#[allow(clippy::too_many_arguments)]
// Translate only source contracts whose historical producer IDs cannot cross
// the organizational-model boundary. Hashing the original coordinates avoids
// lossy character replacement and keeps redelivery identity stable.
fn decode_observation_id(
    event_id: &str,
    tenant_id: &TenantId,
    source_id: &str,
    event_kind: &str,
    schema_ref: &str,
    observed_at_unix_ms: i64,
    attributes: &HashMap<String, String>,
    payload: &serde_json::Value,
) -> Result<ObservationId, AppendLogDecodeError> {
    if is_legacy_okta_threat_insight_candidate(event_id, source_id, event_kind, schema_ref) {
        let provider_domain =
            okta_threat_insight_provider_domain(attributes, payload).ok_or_else(|| {
                AppendLogDecodeError::InvalidModel(
                    "legacy Okta threat insight identity is inconsistent".to_owned(),
                )
            })?;
        if event_id
            != format!("{LEGACY_OKTA_THREAT_INSIGHT_PREFIX}{provider_domain}-{observed_at_unix_ms}")
        {
            return Err(AppendLogDecodeError::InvalidModel(
                "legacy Okta threat insight identity is inconsistent".to_owned(),
            ));
        }
        let mut hasher = Sha256::new();
        hash_field(
            &mut hasher,
            b"cerebro.compat-observation-id.okta-threat-insight/v1",
        );
        hash_field(&mut hasher, tenant_id.as_str().as_bytes());
        hash_field(&mut hasher, source_id.as_bytes());
        hash_field(&mut hasher, event_kind.as_bytes());
        hash_field(&mut hasher, schema_ref.as_bytes());
        hash_field(&mut hasher, observed_at_unix_ms.to_string().as_bytes());
        let mut attributes = attributes.iter().collect::<Vec<_>>();
        attributes.sort_unstable_by(|left, right| left.0.cmp(right.0));
        for (key, value) in attributes {
            if matches!(
                key.as_str(),
                SOURCE_RUNTIME_ID_ATTRIBUTE | SOURCE_COLLECTION_ID_ATTRIBUTE
            ) {
                continue;
            }
            hash_field(&mut hasher, key.as_bytes());
            hash_field(&mut hasher, value.as_bytes());
        }
        hash_field(
            &mut hasher,
            &canonical_event_payload_bytes(source_id, event_kind, schema_ref, payload),
        );
        return compatibility_observation_id(hasher);
    }

    match ObservationId::parse(event_id) {
        Ok(observation_id) => Ok(observation_id),
        Err(error) => match compatible_legacy_invalid_identity(
            event_id, tenant_id, source_id, event_kind, schema_ref, attributes, payload,
        ) {
            Some(LegacyInvalidIdentity::PreservedEventId) => {
                let mut hasher = Sha256::new();
                hash_field(
                    &mut hasher,
                    b"cerebro.compat-observation-id.invalid-character/v1",
                );
                hash_field(&mut hasher, tenant_id.as_str().as_bytes());
                hash_field(&mut hasher, source_id.as_bytes());
                hash_field(&mut hasher, event_kind.as_bytes());
                hash_field(&mut hasher, schema_ref.as_bytes());
                hash_field(&mut hasher, event_id.as_bytes());
                compatibility_observation_id(hasher)
            }
            Some(LegacyInvalidIdentity::SentinelOneApplication) => {
                let mut hasher = Sha256::new();
                hash_field(
                    &mut hasher,
                    SENTINELONE_APPLICATION_COMPATIBILITY_DOMAIN.as_bytes(),
                );
                hash_field(&mut hasher, tenant_id.as_str().as_bytes());
                hash_field(&mut hasher, source_id.as_bytes());
                hash_field(&mut hasher, event_kind.as_bytes());
                hash_field(&mut hasher, schema_ref.as_bytes());
                hash_field(&mut hasher, event_id.as_bytes());
                compatibility_observation_id(hasher)
            }
            Some(LegacyInvalidIdentity::AwsPublicEndpoint(raw_identity)) => {
                let mut hasher = Sha256::new();
                hash_field(
                    &mut hasher,
                    b"cerebro.compat-observation-id.aws-public-endpoint/v1",
                );
                hash_field(&mut hasher, tenant_id.as_str().as_bytes());
                hash_field(&mut hasher, source_id.as_bytes());
                hash_field(&mut hasher, event_kind.as_bytes());
                hash_field(&mut hasher, schema_ref.as_bytes());
                hash_field(&mut hasher, raw_identity.as_bytes());
                hash_field(&mut hasher, event_id.as_bytes());
                compatibility_observation_id(hasher)
            }
            None => Err(model_error(error)),
        },
    }
}

fn is_legacy_okta_threat_insight_candidate(
    event_id: &str,
    source_id: &str,
    event_kind: &str,
    schema_ref: &str,
) -> bool {
    source_id == "okta"
        && event_kind == OKTA_THREAT_INSIGHT_KIND
        && schema_ref == OKTA_THREAT_INSIGHT_SCHEMA_REF
        && event_id.starts_with(LEGACY_OKTA_THREAT_INSIGHT_PREFIX)
        && !event_id.starts_with(CURRENT_OKTA_THREAT_INSIGHT_PREFIX)
}

fn okta_threat_insight_provider_domain(
    attributes: &HashMap<String, String>,
    payload: &serde_json::Value,
) -> Option<String> {
    let attribute_domain = attributes.get("domain")?.trim();
    let payload_domain = payload.get("domain")?.as_str()?.trim();
    if attribute_domain != payload_domain || !is_bounded_provider_domain(attribute_domain) {
        return None;
    }
    Some(attribute_domain.to_owned())
}

fn is_bounded_provider_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

enum LegacyInvalidIdentity<'a> {
    PreservedEventId,
    SentinelOneApplication,
    AwsPublicEndpoint(&'a str),
}

fn compatible_legacy_invalid_identity<'a>(
    event_id: &str,
    tenant_id: &TenantId,
    source_id: &str,
    event_kind: &str,
    schema_ref: &str,
    attributes: &'a HashMap<String, String>,
    payload: &'a serde_json::Value,
) -> Option<LegacyInvalidIdentity<'a>> {
    if event_id.is_empty() {
        return None;
    }
    if sentinelone_application_legacy_identity_is_safe(
        event_id, tenant_id, source_id, event_kind, schema_ref, attributes, payload,
    ) {
        return Some(LegacyInvalidIdentity::SentinelOneApplication);
    }
    match (source_id, event_kind, schema_ref) {
        ("gcp", "gcp.iam_role_assignment", "gcp/iam_role_assignment/v1")
            if gcp_legacy_identity_is_safe(event_id, "gcp-iam-role-assignment-") =>
        {
            Some(LegacyInvalidIdentity::PreservedEventId)
        }
        ("gcp", "gcp.effective_permission", "gcp/effective_permission/v1")
            if gcp_legacy_identity_is_safe(event_id, "gcp-effective-permission-") =>
        {
            Some(LegacyInvalidIdentity::PreservedEventId)
        }
        ("aws", "aws.public_endpoint", "aws/public_endpoint/v1") => {
            let raw_identity =
                compatible_legacy_aws_public_endpoint_identity(event_id, attributes, payload)?;
            if preserves_existing_aws_wildcard_identity(event_id, raw_identity) {
                Some(LegacyInvalidIdentity::PreservedEventId)
            } else {
                Some(LegacyInvalidIdentity::AwsPublicEndpoint(raw_identity))
            }
        }
        _ => None,
    }
}

fn sentinelone_application_legacy_identity_is_safe(
    event_id: &str,
    tenant_id: &TenantId,
    source_id: &str,
    event_kind: &str,
    schema_ref: &str,
    attributes: &HashMap<String, String>,
    payload: &serde_json::Value,
) -> bool {
    if source_id != "sentinelone"
        || event_kind != SENTINELONE_APPLICATION_KIND
        || schema_ref != SENTINELONE_APPLICATION_SCHEMA_REF
    {
        return false;
    }
    let Some(tail) = event_id.strip_prefix(SENTINELONE_APPLICATION_EVENT_ID_PREFIX) else {
        return false;
    };
    if event_id.len() > MAX_SENTINELONE_APPLICATION_EVENT_ID_BYTES
        || tail.is_empty()
        || tail.chars().any(char::is_control)
        || attributes.get("family").map(String::as_str) != Some("application")
    {
        return false;
    }

    let Some(payload_agent_id) = sentinelone_payload_component(payload, "agent_id") else {
        return false;
    };
    let Some(payload_tenant_host) = sentinelone_payload_component(payload, "tenant_host") else {
        return false;
    };
    let Some(payload_name) = sentinelone_optional_payload_component(payload, "name") else {
        return false;
    };
    let Some(payload_publisher) = sentinelone_optional_payload_component(payload, "publisher")
    else {
        return false;
    };
    let Some(payload_version) = sentinelone_optional_payload_component(payload, "version") else {
        return false;
    };
    let Some(attribute_agent_id) = sentinelone_attribute_component(attributes, "agent_id") else {
        return false;
    };
    let Some(attribute_tenant_host) = sentinelone_attribute_component(attributes, "tenant_host")
    else {
        return false;
    };
    let Some(attribute_name) =
        sentinelone_optional_attribute_component(attributes, "application_name")
    else {
        return false;
    };
    let Some(attribute_publisher) =
        sentinelone_optional_attribute_component(attributes, "publisher")
    else {
        return false;
    };
    let Some(attribute_version) = sentinelone_optional_attribute_component(attributes, "version")
    else {
        return false;
    };
    if payload_agent_id != attribute_agent_id
        || payload_tenant_host != attribute_tenant_host
        || payload_name != attribute_name
        || payload_publisher != attribute_publisher
        || payload_version != attribute_version
        || payload_tenant_host != tenant_id.as_str()
    {
        return false;
    }

    let application_parts = [payload_publisher, payload_name, payload_version]
        .into_iter()
        .flatten()
        .map(|value| value.replace(' ', "_"))
        .collect::<Vec<_>>();
    let application_id = if application_parts.is_empty() {
        "unknown".to_owned()
    } else {
        application_parts.join("::")
    };
    let expected = format!(
        "{SENTINELONE_APPLICATION_EVENT_ID_PREFIX}{payload_tenant_host}-{payload_agent_id}-{application_id}"
    );
    expected == event_id
}

fn sentinelone_payload_component<'a>(payload: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    sentinelone_optional_payload_component(payload, key)?
        .as_ref()
        .copied()
}

fn sentinelone_attribute_component<'a>(
    attributes: &'a HashMap<String, String>,
    key: &str,
) -> Option<&'a str> {
    sentinelone_optional_attribute_component(attributes, key)?
        .as_ref()
        .copied()
}

fn sentinelone_optional_payload_component<'a>(
    payload: &'a serde_json::Value,
    key: &str,
) -> Option<Option<&'a str>> {
    match payload.get(key) {
        None => Some(None),
        Some(value) => sentinelone_component_value(Some(value.as_str()?)),
    }
}

fn sentinelone_optional_attribute_component<'a>(
    attributes: &'a HashMap<String, String>,
    key: &str,
) -> Option<Option<&'a str>> {
    match attributes.get(key) {
        None => Some(None),
        Some(value) => sentinelone_component_value(Some(value.as_str())),
    }
}

fn sentinelone_component_value(value: Option<&str>) -> Option<Option<&str>> {
    let value = value?.trim();
    if value.is_empty() {
        return Some(None);
    }
    (value.len() <= MAX_SENTINELONE_APPLICATION_COMPONENT_BYTES
        && !value.chars().any(char::is_control))
    .then_some(Some(value))
}

/// The Go producer derives these identities as
/// `sanitize(member)-sanitize(role)`. Keep this exception closed to the two
/// producer families and to the producer's role-shaped suffix while preserving
/// the original ID in the deterministic compatibility hash below. The caller
/// invokes this only after the model parser rejects the historical ID, so
/// parser-valid public and domain identities retain their original IDs.
fn gcp_legacy_identity_is_safe(event_id: &str, prefix: &str) -> bool {
    let Some(suffix) = event_id.strip_prefix(prefix) else {
        return false;
    };
    let Some(has_bracket_token) = gcp_legacy_identity_charset_is_safe(event_id) else {
        return false;
    };
    if event_id.len() > 256 || suffix.is_empty() || (!event_id.contains('@') && !has_bracket_token)
    {
        return false;
    }

    let Some((separator, _)) = suffix.match_indices("-roles-").last() else {
        return false;
    };
    let principal = &suffix[..separator];
    let role = &suffix[separator + "-roles-".len()..];
    !principal.is_empty()
        && !role.is_empty()
        && role
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/@+%".contains(&byte))
}

/// Return whether the legacy ID uses one optional, non-empty bracket token.
/// Brackets are the only accepted bytes outside the historical identifier
/// charset, and they must be a single balanced pair with safe interior bytes.
fn gcp_legacy_identity_charset_is_safe(event_id: &str) -> Option<bool> {
    let mut bracket_open = false;
    let mut bracket_seen = false;
    let mut bracket_content_len = 0;

    for byte in event_id.bytes() {
        match byte {
            b'[' => {
                if bracket_seen || bracket_open {
                    return None;
                }
                bracket_open = true;
                bracket_seen = true;
                bracket_content_len = 0;
            }
            b']' => {
                if !bracket_open || bracket_content_len == 0 {
                    return None;
                }
                bracket_open = false;
            }
            byte if byte.is_ascii_alphanumeric() || b"-_.:/@+%".contains(&byte) => {
                if bracket_open {
                    bracket_content_len += 1;
                }
            }
            _ => return None,
        }
    }

    (!bracket_open).then_some(bracket_seen)
}

fn compatible_legacy_aws_public_endpoint_identity<'a>(
    event_id: &str,
    attributes: &'a HashMap<String, String>,
    payload: &'a serde_json::Value,
) -> Option<&'a str> {
    const LEGACY_EVENT_ID_PREFIX: &str = "aws-public-endpoint-";
    const MAX_LEGACY_IDENTITY_LEN: usize = 2_048;
    if !event_id.starts_with(LEGACY_EVENT_ID_PREFIX)
        || event_id.len() > LEGACY_EVENT_ID_PREFIX.len() + MAX_LEGACY_IDENTITY_LEN
    {
        return None;
    }
    let account_id = match payload
        .get("account_id")
        .and_then(serde_json::Value::as_str)
    {
        Some(account_id) if !account_id.trim().is_empty() => account_id.trim(),
        _ => return None,
    };
    if attributes.get("domain").map(String::as_str) != Some(account_id) {
        return None;
    }
    let endpoint = payload
        .get("endpoint")
        .and_then(serde_json::Value::as_object)?;
    let identity_fields = [
        ("endpoint_id", "EndpointID"),
        ("resource_id", "ResourceID"),
        ("ip", "IP"),
        ("host", "Host"),
    ];
    let mut identity = None;
    for (attribute_key, payload_key) in identity_fields {
        let payload_value = trimmed_json_string(endpoint, payload_key)?;
        let attribute_value = attributes.get(attribute_key).map(String::as_str);
        if attribute_value != (!payload_value.is_empty()).then_some(payload_value) {
            return None;
        }
        if identity.is_none() && !payload_value.is_empty() {
            identity = Some(payload_value);
        }
    }
    for (attribute_key, payload_key) in [("service", "Service"), ("resource_type", "ResourceType")]
    {
        let payload_value = trimmed_json_string(endpoint, payload_key)?;
        if attributes.get(attribute_key).map(String::as_str)
            != (!payload_value.is_empty()).then_some(payload_value)
        {
            return None;
        }
    }
    let identity = identity?;
    if identity.len() > MAX_LEGACY_IDENTITY_LEN {
        return None;
    }
    (event_id == sanitize_legacy_aws_event_id(&format!("{LEGACY_EVENT_ID_PREFIX}{identity}")))
        .then_some(identity)
}

fn preserves_existing_aws_wildcard_identity(event_id: &str, raw_identity: &str) -> bool {
    event_id.len() <= 256
        && event_id.contains('*')
        && event_id.strip_prefix("aws-public-endpoint-") == Some(raw_identity)
        && event_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/*".contains(&byte))
}

fn trimmed_json_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a str> {
    match object.get(key) {
        None => Some(""),
        Some(serde_json::Value::String(value)) => Some(value.trim()),
        Some(_) => None,
    }
}

fn sanitize_legacy_aws_event_id(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            ' ' | '/' | ':' => '-',
            other => other,
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

fn compatibility_observation_id(hasher: Sha256) -> Result<ObservationId, AppendLogDecodeError> {
    ObservationId::parse(format!(
        "{COMPATIBILITY_OBSERVATION_ID_PREFIX}{}",
        finish_digest(hasher)
    ))
    .map_err(model_error)
}

fn canonical_event_payload_bytes(
    source_id: &str,
    event_kind: &str,
    schema_ref: &str,
    payload: &serde_json::Value,
) -> Vec<u8> {
    let mut payload = payload.clone();
    // The v1 API models excluded zones as a set. Its historical producer kept
    // provider order, so equivalent deliveries need one semantic digest.
    if source_id == "okta"
        && event_kind == OKTA_THREAT_INSIGHT_KIND
        && schema_ref == OKTA_THREAT_INSIGHT_SCHEMA_REF
        && let Some(zones) = payload
            .as_object_mut()
            .and_then(|object| object.get_mut("exclude_zones"))
            .and_then(serde_json::Value::as_array_mut)
        && zones.iter().all(serde_json::Value::is_string)
    {
        zones.sort_unstable_by(|left, right| {
            left.as_str()
                .expect("checked string zone")
                .cmp(right.as_str().expect("checked string zone"))
        });
    }
    canonical_payload_bytes(&payload)
}

fn canonical_payload_bytes(value: &serde_json::Value) -> Vec<u8> {
    fn canonicalize(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.iter().map(canonicalize).collect())
            }
            serde_json::Value::Object(values) => {
                let mut keys = values.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                let mut canonical = serde_json::Map::new();
                for key in keys {
                    canonical.insert(key.clone(), canonicalize(&values[key]));
                }
                serde_json::Value::Object(canonical)
            }
            scalar => scalar.clone(),
        }
    }

    serde_json::to_vec(&canonicalize(value)).expect("validated JSON payload must serialize")
}

fn finish_digest(hasher: Sha256) -> String {
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn required<'a>(value: &'a str, field: &'static str) -> Result<&'a str, AppendLogDecodeError> {
    let value = value.trim();
    if value.is_empty() {
        Err(AppendLogDecodeError::Missing(field))
    } else {
        Ok(value)
    }
}

fn timestamp_millis(value: Timestamp) -> Result<i64, AppendLogDecodeError> {
    if value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos) {
        return Err(AppendLogDecodeError::InvalidTimestamp);
    }
    value
        .seconds
        .checked_mul(1_000)
        .and_then(|seconds| seconds.checked_add(i64::from(value.nanos) / 1_000_000))
        .filter(|value| *value > 0)
        .ok_or(AppendLogDecodeError::InvalidTimestamp)
}

fn model_error(error: impl fmt::Display) -> AppendLogDecodeError {
    AppendLogDecodeError::InvalidModel(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(wire: CommittedSourceWire) -> Vec<u8> {
        wire.encode_to_vec()
    }

    fn source_wire() -> CommittedSourceWire {
        CommittedSourceWire {
            id: "event-1".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            source_id: "box".to_owned(),
            kind: "box.content_assets".to_owned(),
            occurred_at: Some(Timestamp {
                seconds: 1_720_000_000,
                nanos: 123_000_000,
            }),
            schema_ref: "box/content_assets/v1".to_owned(),
            payload: br#"{"id":"file-1","name":"board.pdf"}"#.to_vec(),
            attributes: HashMap::from([
                ("source_runtime_id".to_owned(), "box-prod".to_owned()),
                ("provider_id".to_owned(), "file-1".to_owned()),
            ]),
        }
    }

    fn sentinelone_application_wire(event_id: &str) -> CommittedSourceWire {
        let mut wire = source_wire();
        wire.id = event_id.to_owned();
        wire.tenant_id = "sentinelone.example.test".to_owned();
        wire.source_id = "sentinelone".to_owned();
        wire.kind = "sentinelone.application_inventory".to_owned();
        wire.schema_ref = "sentinelone/application_inventory/v1".to_owned();
        wire.attributes = HashMap::from([
            (
                SOURCE_RUNTIME_ID_ATTRIBUTE.to_owned(),
                "sentinelone-runtime".to_owned(),
            ),
            ("family".to_owned(), "application".to_owned()),
            ("agent_id".to_owned(), "agent-fixture-1".to_owned()),
            (
                "tenant_host".to_owned(),
                "sentinelone.example.test".to_owned(),
            ),
            ("application_name".to_owned(), "Example App".to_owned()),
            ("publisher".to_owned(), "(Example Inc)".to_owned()),
            ("version".to_owned(), "1.0.0".to_owned()),
        ]);
        wire.payload = serde_json::to_vec(&serde_json::json!({
            "agent_id": "agent-fixture-1",
            "tenant_host": "sentinelone.example.test",
            "name": "Example App",
            "publisher": "(Example Inc)",
            "version": "1.0.0",
            "installed_date": "2026-04-20T00:00:00Z",
            "size_bytes": 12345,
            "raw": {
                "name": "Example App",
                "publisher": "(Example Inc)",
                "version": "1.0.0"
            }
        }))
        .unwrap();
        wire
    }

    fn legacy_aws_endpoint_wire(identity: &str) -> CommittedSourceWire {
        let identity = identity.trim();
        let mut wire = source_wire();
        wire.tenant_id = "tenant-a".to_owned();
        wire.source_id = "aws".to_owned();
        wire.kind = "aws.public_endpoint".to_owned();
        wire.schema_ref = "aws/public_endpoint/v1".to_owned();
        wire.id = sanitize_legacy_aws_event_id(&format!("aws-public-endpoint-{identity}"));
        wire.attributes = HashMap::from([
            (
                SOURCE_RUNTIME_ID_ATTRIBUTE.to_owned(),
                "aws-runtime".to_owned(),
            ),
            ("domain".to_owned(), "123456789012".to_owned()),
            ("endpoint_id".to_owned(), identity.to_owned()),
            ("resource_type".to_owned(), "route53_record".to_owned()),
            ("service".to_owned(), "route53".to_owned()),
        ]);
        wire.payload = serde_json::to_vec(&serde_json::json!({
            "account_id": "123456789012",
            "endpoint": {
                "EndpointID": identity,
                "ResourceID": "",
                "IP": "",
                "Host": "",
                "ResourceType": "route53_record",
                "Service": "route53"
            }
        }))
        .unwrap();
        wire
    }

    #[test]
    fn canonical_source_event_becomes_a_sealed_committed_event() {
        let event = CommittedSourceEvent::decode(&encode(source_wire()))
            .unwrap()
            .unwrap();
        assert_eq!(event.tenant_id().as_str(), "tenant-a");
        assert_eq!(event.source_runtime_id().as_str(), "box-prod");
        assert_eq!(event.observation_id().as_str(), "event-1");
        assert_eq!(event.source_id(), "box");
        assert_eq!(event.family_id(), "content_assets");
        assert_eq!(event.event_kind(), "box.content_assets");
        assert_eq!(event.schema_ref(), "box/content_assets/v1");
        assert_eq!(event.collection_id().unwrap().as_str(), "event:event-1");
        assert_eq!(event.observed_at_unix_ms(), 1_720_000_000_123);
        assert_eq!(event.attributes()["provider_id"], "file-1");
        assert_eq!(event.payload()["name"], "board.pdf");
    }

    #[test]
    fn sentinelone_legacy_application_identity_is_accepted() {
        let id = "sentinelone-application-sentinelone.example.test-agent-fixture-1-(Example_Inc)::Example_App::1.0.0";
        let event = CommittedSourceEvent::decode(&encode(sentinelone_application_wire(id)))
            .expect("SentinelOne legacy application identity should decode")
            .expect("source event");
        assert!(event.observation_id().as_str().starts_with("compat:v1:"));
    }

    #[test]
    fn sentinelone_parser_valid_application_identity_is_preserved() {
        let id = "sentinelone-application-sentinelone.example.test-agent-fixture-1-Example_Inc::Example_App::1.0.0";
        let event = CommittedSourceEvent::decode(&encode(sentinelone_application_wire(id)))
            .expect("parser-valid SentinelOne identity should decode")
            .expect("source event");
        assert_eq!(event.observation_id().as_str(), id);
    }

    #[test]
    fn sentinelone_legacy_application_identity_is_redelivery_stable_without_provenance() {
        let id = "sentinelone-application-sentinelone.example.test-agent-fixture-1-(Example_Inc)::Example_App::1.0.0";
        let wire = sentinelone_application_wire(id);
        let first = CommittedSourceEvent::decode(&encode(wire.clone()))
            .expect("first SentinelOne identity should decode")
            .expect("source event");
        let second = CommittedSourceEvent::decode(&encode(wire.clone()))
            .expect("redelivery SentinelOne identity should decode")
            .expect("source event");
        assert_eq!(first.observation_id(), second.observation_id());

        let mut delivery_variant = wire;
        delivery_variant.attributes.insert(
            SOURCE_RUNTIME_ID_ATTRIBUTE.to_owned(),
            "sentinelone-runtime-retry".to_owned(),
        );
        delivery_variant.attributes.insert(
            SOURCE_COLLECTION_ID_ATTRIBUTE.to_owned(),
            "collection-retry".to_owned(),
        );
        let retry = CommittedSourceEvent::decode(&encode(delivery_variant))
            .expect("delivery variant should decode")
            .expect("source event");
        assert_eq!(first.observation_id(), retry.observation_id());
    }

    fn assert_sentinelone_application_rejected(label: &str, wire: CommittedSourceWire) {
        assert!(
            matches!(
                CommittedSourceEvent::decode(&encode(wire)),
                Err(AppendLogDecodeError::InvalidModel(_))
            ),
            "{label}"
        );
    }

    #[test]
    fn sentinelone_legacy_application_identity_rejects_adjacent_and_malformed_contracts() {
        let id = "sentinelone-application-sentinelone.example.test-agent-fixture-1-(Example_Inc)::Example_App::1.0.0";

        let mut wrong_source = sentinelone_application_wire(id);
        wrong_source.source_id = "other".to_owned();
        wrong_source.kind = "other.application_inventory".to_owned();
        wrong_source.schema_ref = "other/application_inventory/v1".to_owned();
        assert_sentinelone_application_rejected("cross-source identity was accepted", wrong_source);

        let mut wrong_kind = sentinelone_application_wire(id);
        wrong_kind.kind = "sentinelone.threat".to_owned();
        wrong_kind.schema_ref = "sentinelone/threat/v1".to_owned();
        assert_sentinelone_application_rejected("cross-family identity was accepted", wrong_kind);

        let mut wrong_schema = sentinelone_application_wire(id);
        wrong_schema.schema_ref = "sentinelone/application_inventory/v2".to_owned();
        assert_sentinelone_application_rejected("cross-schema identity was accepted", wrong_schema);

        let mut bad_prefix = sentinelone_application_wire(id);
        bad_prefix.id = id.replacen(
            SENTINELONE_APPLICATION_EVENT_ID_PREFIX,
            "sentinelone-app-",
            1,
        );
        assert_sentinelone_application_rejected("bad producer prefix was accepted", bad_prefix);

        let mut tenant_mismatch = sentinelone_application_wire(id);
        tenant_mismatch.tenant_id = "other.example.test".to_owned();
        assert_sentinelone_application_rejected("tenant mismatch was accepted", tenant_mismatch);

        let mut attribute_mismatch = sentinelone_application_wire(id);
        attribute_mismatch
            .attributes
            .insert("publisher".to_owned(), "Different Inc".to_owned());
        assert_sentinelone_application_rejected(
            "attribute/payload disagreement was accepted",
            attribute_mismatch,
        );

        let mut agent_mismatch = sentinelone_application_wire(id);
        agent_mismatch
            .attributes
            .insert("agent_id".to_owned(), "other-agent".to_owned());
        assert_sentinelone_application_rejected(
            "agent attribute/payload disagreement was accepted",
            agent_mismatch,
        );

        let mut reconstructed_id_mismatch = sentinelone_application_wire(id);
        reconstructed_id_mismatch.id =
            "sentinelone-application-sentinelone.example.test-agent-fixture-1-(Example_Inc)::Other_App::1.0.0"
                .to_owned();
        assert_sentinelone_application_rejected(
            "identity differing from the reconstructed Go ID was accepted",
            reconstructed_id_mismatch,
        );

        let mut control_tail = sentinelone_application_wire(id);
        control_tail.id =
            "sentinelone-application-sentinelone.example.test-agent-fixture-1-(Example_\u{1})::Example_App::1.0.0"
                .to_owned();
        assert_sentinelone_application_rejected(
            "control byte in legacy tail was accepted",
            control_tail,
        );

        let mut overlong_tail = sentinelone_application_wire(id);
        overlong_tail.id = format!("{id}{}", "x".repeat(256));
        assert_sentinelone_application_rejected(
            "overlong legacy identity was accepted",
            overlong_tail,
        );
    }

    #[test]
    fn sentinelone_legacy_application_identity_mirrors_optional_go_application_id_parts() {
        let id = "sentinelone-application-sentinelone.example.test-agent-fixture-1-unknown";
        let mut wire = sentinelone_application_wire(id);
        let mut payload: serde_json::Value = serde_json::from_slice(&wire.payload).unwrap();
        for key in ["name", "publisher", "version"] {
            payload.as_object_mut().unwrap().remove(key);
        }
        wire.payload = serde_json::to_vec(&payload).unwrap();
        for key in ["application_name", "publisher", "version"] {
            wire.attributes.remove(key);
        }
        let event = CommittedSourceEvent::decode(&encode(wire))
            .expect("optional Go application ID parts should decode")
            .expect("source event");
        assert_eq!(event.observation_id().as_str(), id);
    }

    #[test]
    fn sentinelone_legacy_application_identity_mirrors_one_optional_invalid_go_id_part() {
        let id = "sentinelone-application-sentinelone.example.test-agent-fixture-1-(Example_App)";
        let mut wire = sentinelone_application_wire(id);
        wire.payload = serde_json::to_vec(&serde_json::json!({
            "agent_id": "agent-fixture-1",
            "tenant_host": "sentinelone.example.test",
            "name": "(Example App)"
        }))
        .unwrap();
        wire.attributes
            .insert("application_name".to_owned(), "(Example App)".to_owned());
        wire.attributes.remove("publisher");
        wire.attributes.remove("version");
        let event = CommittedSourceEvent::decode(&encode(wire))
            .expect("one optional invalid Go ID part should decode")
            .expect("source event");
        assert!(event.observation_id().as_str().starts_with("compat:v1:"));
    }

    #[test]
    fn compatible_legacy_observation_ids_preserve_parse_first_semantics() {
        let compatibility_cases = [
            (
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-user+alias@example.test-roles-owner",
            ),
            (
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-user+alias@example.test-roles-owner",
            ),
            (
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-principal[workload-identity]-roles-viewer",
            ),
            (
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-principal[workload-identity]-roles-viewer",
            ),
        ];

        for (kind, schema_ref, id) in compatibility_cases {
            let mut wire = source_wire();
            wire.source_id = "gcp".to_owned();
            wire.kind = kind.to_owned();
            wire.schema_ref = schema_ref.to_owned();
            wire.id = id.to_owned();

            let first = CommittedSourceEvent::decode(&encode(wire.clone()))
                .expect("legacy compatibility ID should decode")
                .expect("source event");
            let second = CommittedSourceEvent::decode(&encode(wire))
                .expect("redelivery should decode")
                .expect("source event");

            assert_eq!(first.observation_id(), second.observation_id(), "{id}");
            assert_ne!(first.observation_id().as_str(), id, "{id}");
            assert!(first.observation_id().as_str().starts_with("compat:v1:"));
        }

        let parser_valid_cases = [
            (
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-allUsers-roles-viewer",
            ),
            (
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-allAuthenticatedUsers-roles-viewer",
            ),
            (
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-writer.com-roles-viewer",
            ),
            (
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-allUsers-roles-viewer",
            ),
            (
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-allAuthenticatedUsers-roles-viewer",
            ),
            (
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-writer.com-roles-viewer",
            ),
        ];

        for (kind, schema_ref, id) in parser_valid_cases {
            let mut wire = source_wire();
            wire.source_id = "gcp".to_owned();
            wire.kind = kind.to_owned();
            wire.schema_ref = schema_ref.to_owned();
            wire.id = id.to_owned();

            let event = CommittedSourceEvent::decode(&encode(wire))
                .expect("parser-valid producer ID should decode")
                .expect("source event");
            assert_eq!(event.observation_id().as_str(), id);
        }
    }

    #[test]
    fn malformed_gcp_legacy_ids_remain_rejected() {
        let cases = [
            (
                "gcp",
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-user@example.test?",
            ),
            (
                "gcp",
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-user\\alias@example.test-roles-owner",
            ),
            (
                "gcp",
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-user@example.test-roles-owner?",
            ),
            (
                "gcp",
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-user@example.test-role-owner",
            ),
            (
                "gcp",
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-principal[workload-identity-roles-owner",
            ),
            (
                "gcp",
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-principalworkload-identity]-roles-owner",
            ),
            (
                "gcp",
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-principal[]-roles-owner",
            ),
            (
                "gcp",
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-principal[[workload]]-roles-owner",
            ),
            (
                "gcp",
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-principal[workload?]-roles-owner",
            ),
            (
                "gcp",
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-effective-permission-user@example.test-roles-owner",
            ),
            (
                "gcp",
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-iam-role-assignment-user@example.test-roles-owner",
            ),
            (
                "other",
                "other.iam_role_assignment",
                "other/iam_role_assignment/v1",
                "gcp-iam-role-assignment-user@example.test-roles-owner",
            ),
        ];
        for (source_id, kind, schema_ref, id) in cases {
            let mut wire = source_wire();
            wire.source_id = source_id.to_owned();
            wire.kind = kind.to_owned();
            wire.schema_ref = schema_ref.to_owned();
            wire.id = id.to_owned();
            assert!(
                matches!(
                    CommittedSourceEvent::decode(&encode(wire)),
                    Err(AppendLogDecodeError::InvalidModel(message))
                        if message == "observation id is invalid"
                ),
                "{source_id} {kind} {id}"
            );
        }

        let mut oversized = source_wire();
        oversized.source_id = "gcp".to_owned();
        oversized.kind = "gcp.effective_permission".to_owned();
        oversized.schema_ref = "gcp/effective_permission/v1".to_owned();
        oversized.id = format!(
            "gcp-effective-permission-user@example.test-roles-{}?",
            "x".repeat(256),
        );
        assert!(matches!(
            CommittedSourceEvent::decode(&encode(oversized)),
            Err(AppendLogDecodeError::InvalidModel(message))
                if message == "observation id is invalid"
        ));
    }

    #[test]
    fn compatibility_identity_binds_tenant_and_contract_not_delivery_provenance() {
        for id in [
            "gcp-effective-permission-user@example.test-roles-owner",
            "gcp-effective-permission-principal[workload-identity]-roles-viewer",
        ] {
            let mut first_wire = source_wire();
            first_wire.source_id = "gcp".to_owned();
            first_wire.kind = "gcp.effective_permission".to_owned();
            first_wire.schema_ref = "gcp/effective_permission/v1".to_owned();
            first_wire.id = id.to_owned();
            let first = CommittedSourceEvent::decode(&encode(first_wire.clone()))
                .unwrap()
                .unwrap();

            let mut redelivery_wire = first_wire.clone();
            redelivery_wire.attributes.insert(
                SOURCE_RUNTIME_ID_ATTRIBUTE.to_owned(),
                "gcp-replacement".to_owned(),
            );
            redelivery_wire.attributes.insert(
                SOURCE_COLLECTION_ID_ATTRIBUTE.to_owned(),
                "replacement-collection".to_owned(),
            );
            let redelivery = CommittedSourceEvent::decode(&encode(redelivery_wire))
                .unwrap()
                .unwrap();
            assert_eq!(first.observation_id(), redelivery.observation_id(), "{id}");
            assert_eq!(first.record_digest(), redelivery.record_digest(), "{id}");
            assert_ne!(
                first.attributes_digest(),
                redelivery.attributes_digest(),
                "{id}"
            );

            let mut other_tenant_wire = first_wire;
            other_tenant_wire.tenant_id = "tenant-b".to_owned();
            let other_tenant = CommittedSourceEvent::decode(&encode(other_tenant_wire))
                .unwrap()
                .unwrap();
            assert_ne!(
                first.observation_id(),
                other_tenant.observation_id(),
                "{id}"
            );
            assert_ne!(first.record_digest(), other_tenant.record_digest(), "{id}");
        }
    }

    #[test]
    fn compatibility_identity_boundary_stays_closed() {
        let cases = [
            (
                "box",
                "box.content_assets",
                "box/content_assets/v1",
                "user@example.test",
            ),
            (
                "gcp",
                "gcp.project_bindings",
                "gcp/project_bindings/v1",
                "gcp-iam-role-assignment-user@example.test-roles-owner",
            ),
            (
                "gcp",
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-user\\alias@example.test-roles-owner",
            ),
            (
                "aws",
                "aws.public_endpoint",
                "aws/public_endpoint/v1",
                "aws-public-endpoint-host@example.test",
            ),
        ];
        for (source, kind, schema, id) in cases {
            let mut wire = source_wire();
            wire.source_id = source.to_owned();
            wire.kind = kind.to_owned();
            wire.schema_ref = schema.to_owned();
            wire.id = id.to_owned();
            assert!(matches!(
                CommittedSourceEvent::decode(&encode(wire)),
                Err(AppendLogDecodeError::InvalidModel(message))
                    if message == "observation id is invalid"
            ));
        }
    }

    #[test]
    fn legacy_aws_wildcard_endpoint_gets_a_collision_resistant_identity() {
        let wire = legacy_aws_endpoint_wire("*.example.test");

        let event = CommittedSourceEvent::decode(&encode(wire))
            .unwrap()
            .unwrap();
        assert_eq!(
            event.observation_id().as_str(),
            "compat:v1:c5346b4c728737c7f4a0a7b103df9c9daca8527f8c2e11a63bb3e0968c621c27"
        );
    }

    #[test]
    fn legacy_aws_endpoint_identity_requires_exact_source_material() {
        let mut wire = legacy_aws_endpoint_wire("blue@edge");

        let event = CommittedSourceEvent::decode(&encode(wire.clone()))
            .expect("producer-bound legacy endpoint should decode")
            .expect("source event");
        assert!(event.observation_id().as_str().starts_with("compat:v1:"));

        wire.payload = serde_json::to_vec(&serde_json::json!({
            "account_id": "123456789012",
            "endpoint": {
                "EndpointID": "other@edge",
                "ResourceID": "",
                "IP": "",
                "Host": "",
                "ResourceType": "route53_record",
                "Service": "route53"
            }
        }))
        .unwrap();
        assert!(matches!(
            CommittedSourceEvent::decode(&encode(wire)),
            Err(AppendLogDecodeError::InvalidModel(message))
                if message == "observation id is invalid"
        ));
    }

    #[test]
    fn legacy_aws_endpoint_identity_replays_stably_and_remains_tenant_scoped() {
        let wire = legacy_aws_endpoint_wire("weighted@edge");
        let first = CommittedSourceEvent::decode(&encode(wire.clone()))
            .unwrap()
            .unwrap();
        let redelivery = CommittedSourceEvent::decode(&encode(wire.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(first.observation_id(), redelivery.observation_id());

        let mut other_tenant = wire;
        other_tenant.tenant_id = "tenant-b".to_owned();
        let other_tenant = CommittedSourceEvent::decode(&encode(other_tenant))
            .unwrap()
            .unwrap();
        assert_ne!(first.observation_id(), other_tenant.observation_id());
    }

    #[test]
    fn legacy_aws_endpoint_identity_distinguishes_sanitizer_collisions() {
        let slash = CommittedSourceEvent::decode(&encode(legacy_aws_endpoint_wire("blue/edge@id")))
            .unwrap()
            .unwrap();
        let colon = CommittedSourceEvent::decode(&encode(legacy_aws_endpoint_wire("blue:edge@id")))
            .unwrap()
            .unwrap();

        assert_ne!(slash.observation_id(), colon.observation_id());
        assert_ne!(slash.record_digest(), colon.record_digest());
    }

    #[test]
    fn legacy_aws_endpoint_identity_matches_go_trimming_and_sanitization() {
        let mut wire = legacy_aws_endpoint_wire("weighted @ edge:/");
        wire.id = "aws-public-endpoint-weighted-@-edge".to_owned();
        wire.payload = serde_json::to_vec(&serde_json::json!({
            "account_id": "123456789012",
            "endpoint": {
                "EndpointID": " weighted @ edge:/ ",
                "ResourceID": "", "IP": "", "Host": "",
                "ResourceType": "route53_record", "Service": "route53"
            }
        }))
        .unwrap();
        let event = CommittedSourceEvent::decode(&encode(wire))
            .unwrap()
            .unwrap();
        assert!(event.observation_id().as_str().starts_with("compat:v1:"));
    }

    #[test]
    fn legacy_aws_endpoint_identity_requires_account_and_endpoint_metadata_binding() {
        let baseline = legacy_aws_endpoint_wire("weighted@edge");
        let cases = [
            (
                "account",
                serde_json::json!({
                    "account_id": "210987654321",
                    "endpoint": {
                        "EndpointID": "weighted@edge",
                        "ResourceID": "", "IP": "", "Host": "",
                        "ResourceType": "route53_record", "Service": "route53"
                    }
                }),
            ),
            (
                "service",
                serde_json::json!({
                    "account_id": "123456789012",
                    "endpoint": {
                        "EndpointID": "weighted@edge",
                        "ResourceID": "", "IP": "", "Host": "",
                        "ResourceType": "route53_record", "Service": "other"
                    }
                }),
            ),
            (
                "missing endpoint",
                serde_json::json!({"account_id": "123456789012"}),
            ),
        ];
        for (field, payload) in cases {
            let mut wire = baseline.clone();
            wire.payload = serde_json::to_vec(&payload).unwrap();
            assert!(
                CommittedSourceEvent::decode(&encode(wire)).is_err(),
                "changed {field} escaped producer binding"
            );
        }
    }

    #[test]
    fn legacy_aws_endpoint_identity_has_an_explicit_producer_bound() {
        let maximum = format!("@{}", "a".repeat(2_047));
        assert!(CommittedSourceEvent::decode(&encode(legacy_aws_endpoint_wire(&maximum))).is_ok());

        let oversized = format!("@{}", "a".repeat(2_048));
        assert!(matches!(
            CommittedSourceEvent::decode(&encode(legacy_aws_endpoint_wire(&oversized))),
            Err(AppendLogDecodeError::InvalidModel(message))
                if message == "observation id is invalid"
        ));
    }

    #[test]
    fn non_source_event_is_not_claimed_by_the_consumer() {
        let mut wire = source_wire();
        wire.source_id.clear();
        wire.kind = "sec.findings.v1.recorded".to_owned();
        assert_eq!(CommittedSourceEvent::decode(&encode(wire)).unwrap(), None);
    }

    #[test]
    fn source_owned_envelope_cannot_bypass_required_fields() {
        for mutate in [
            |wire: &mut CommittedSourceWire| wire.id.clear(),
            |wire: &mut CommittedSourceWire| wire.tenant_id.clear(),
            |wire: &mut CommittedSourceWire| wire.occurred_at = None,
            |wire: &mut CommittedSourceWire| {
                wire.attributes.remove(SOURCE_RUNTIME_ID_ATTRIBUTE);
            },
        ] {
            let mut wire = source_wire();
            mutate(&mut wire);
            assert!(CommittedSourceEvent::decode(&encode(wire)).is_err());
        }
    }

    #[test]
    fn source_kind_must_belong_to_the_declared_source() {
        let mut wire = source_wire();
        wire.kind = "github.repositories".to_owned();
        assert!(matches!(
            CommittedSourceEvent::decode(&encode(wire)),
            Err(AppendLogDecodeError::Missing(_))
        ));
    }

    #[test]
    fn portable_security_lifecycle_event_keeps_its_protobuf_payload() {
        let mut wire = source_wire();
        wire.kind = CREDENTIAL_EVENT_KIND.to_owned();
        wire.schema_ref = CREDENTIAL_SCHEMA_REF.to_owned();
        wire.payload = vec![0x0a, 0x00];
        let event = CommittedSourceEvent::decode(&encode(wire))
            .unwrap()
            .unwrap();
        assert_eq!(event.event_kind(), CREDENTIAL_EVENT_KIND);
        assert_eq!(event.schema_ref(), CREDENTIAL_SCHEMA_REF);
        assert_eq!(event.family_id(), CREDENTIAL_EVENT_KIND);
        assert_eq!(event.raw_payload(), &[0x0a, 0x00]);
    }

    #[test]
    fn portable_security_lifecycle_event_requires_the_exact_schema() {
        let mut wire = source_wire();
        wire.kind = CERTIFICATE_EVENT_KIND.to_owned();
        wire.schema_ref = CREDENTIAL_SCHEMA_REF.to_owned();
        assert!(matches!(
            CommittedSourceEvent::decode(&encode(wire)),
            Err(AppendLogDecodeError::Missing(_))
        ));
    }

    #[test]
    fn payload_must_be_json() {
        let mut wire = source_wire();
        wire.payload = b"not-json".to_vec();
        assert!(matches!(
            CommittedSourceEvent::decode(&encode(wire)),
            Err(AppendLogDecodeError::InvalidPayload(_))
        ));
    }

    #[test]
    fn timestamp_must_be_positive_and_normalized() {
        for timestamp in [
            Timestamp {
                seconds: 0,
                nanos: 0,
            },
            Timestamp {
                seconds: 1,
                nanos: -1,
            },
            Timestamp {
                seconds: 1,
                nanos: 1_000_000_000,
            },
        ] {
            let mut wire = source_wire();
            wire.occurred_at = Some(timestamp);
            assert_eq!(
                CommittedSourceEvent::decode(&encode(wire)).unwrap_err(),
                AppendLogDecodeError::InvalidTimestamp
            );
        }
    }

    #[test]
    fn committed_event_builds_the_only_allowed_incremental_batch() {
        let event = CommittedSourceEvent::decode(&encode(source_wire()))
            .unwrap()
            .unwrap();
        let batch = event
            .into_batch("box.asset".to_owned(), "file-1".to_owned())
            .unwrap();
        assert_eq!(batch.scope.receipt().tenant_id().as_str(), "tenant-a");
        assert_eq!(
            batch.scope.receipt().source_runtime_id().as_str(),
            "box-prod"
        );
        assert_eq!(batch.scope.receipt().scope(), "box.content_assets");
        assert_eq!(batch.records[0].provider_kind, "box.asset");
        assert_eq!(batch.records[0].provider_id, "file-1");
    }

    #[test]
    fn empty_payload_is_an_empty_object() {
        let mut wire = source_wire();
        wire.payload.clear();
        let event = CommittedSourceEvent::decode(&encode(wire))
            .unwrap()
            .unwrap();
        assert_eq!(event.payload(), &serde_json::json!({}));
    }

    #[test]
    fn record_digest_is_stable_across_attribute_and_payload_key_order() {
        let mut wire = source_wire();
        wire.payload = br#"{"nested":{"z":1,"a":2},"id":"file-1","name":"board.pdf"}"#.to_vec();
        let first = CommittedSourceEvent::decode(&encode(wire))
            .unwrap()
            .unwrap();
        let input = CommittedSourceInput {
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            source_runtime_id: SourceRuntimeId::parse("box-prod").unwrap(),
            observation_id: ObservationId::parse("event-1").unwrap(),
            source_id: "box".to_owned(),
            family_id: "content_assets".to_owned(),
            event_kind: "box.content_assets".to_owned(),
            schema_ref: "box/content_assets/v1".to_owned(),
            observed_at_unix_ms: 1_720_000_000_123,
            attributes: BTreeMap::from([
                ("provider_id".to_owned(), "file-1".to_owned()),
                ("source_runtime_id".to_owned(), "box-prod".to_owned()),
            ]),
            payload: serde_json::json!({
                "name": "board.pdf",
                "id": "file-1",
                "nested": {"a": 2, "z": 1}
            }),
        };
        let second = CommittedSourceEvent::from_input(input).unwrap();
        assert_eq!(first.record_digest(), second.record_digest());
        assert_eq!(first.payload_digest(), second.payload_digest());
    }

    #[test]
    fn legacy_threat_insight_zone_order_is_idempotent() {
        let mut first_wire = source_wire();
        first_wire.id = "okta-threat-insight-example.okta.test-1720000000123".to_owned();
        first_wire.tenant_id = "tenant-a".to_owned();
        first_wire.source_id = "okta".to_owned();
        first_wire.kind = "okta.threat_insight".to_owned();
        first_wire.schema_ref = "okta/threat_insight/v1".to_owned();
        first_wire.payload = br#"{"action":"block","domain":"example.okta.test","exclude_zones":["zone-b","zone-a"]}"#.to_vec();
        first_wire.attributes = HashMap::from([
            (
                SOURCE_RUNTIME_ID_ATTRIBUTE.to_owned(),
                "okta-runtime".to_owned(),
            ),
            ("action".to_owned(), "block".to_owned()),
            ("domain".to_owned(), "example.okta.test".to_owned()),
            ("exclude_zone_count".to_owned(), "2".to_owned()),
            ("family".to_owned(), "threat_insight".to_owned()),
            ("resource_id".to_owned(), "threat_insight_config".to_owned()),
            (
                "resource_type".to_owned(),
                "ThreatInsightConfiguration".to_owned(),
            ),
        ]);

        let mut second_wire = first_wire.clone();
        second_wire.payload = br#"{"exclude_zones":["zone-a","zone-b"],"domain":"example.okta.test","action":"block"}"#.to_vec();

        let first = CommittedSourceEvent::decode(&encode(first_wire))
            .unwrap()
            .unwrap();
        let second = CommittedSourceEvent::decode(&encode(second_wire))
            .unwrap()
            .unwrap();

        assert_eq!(first.observation_id(), second.observation_id());
        assert!(first.observation_id().as_str().starts_with("compat:v1:"));
        assert_eq!(first.record_digest(), second.record_digest());
        assert_eq!(first.payload_digest(), second.payload_digest());
    }

    #[test]
    fn legacy_threat_insight_conflicting_material_remains_distinct() {
        let mut first_wire = source_wire();
        first_wire.id = "okta-threat-insight-example.okta.test-1720000000123".to_owned();
        first_wire.tenant_id = "tenant-a".to_owned();
        first_wire.source_id = "okta".to_owned();
        first_wire.kind = OKTA_THREAT_INSIGHT_KIND.to_owned();
        first_wire.schema_ref = OKTA_THREAT_INSIGHT_SCHEMA_REF.to_owned();
        first_wire.payload =
            br#"{"action":"block","domain":"example.okta.test","exclude_zones":["zone-a"]}"#
                .to_vec();
        first_wire.attributes = HashMap::from([
            (
                SOURCE_RUNTIME_ID_ATTRIBUTE.to_owned(),
                "okta-runtime".to_owned(),
            ),
            ("action".to_owned(), "block".to_owned()),
            ("domain".to_owned(), "example.okta.test".to_owned()),
            ("exclude_zone_count".to_owned(), "1".to_owned()),
            ("family".to_owned(), "threat_insight".to_owned()),
            ("resource_id".to_owned(), "threat_insight_config".to_owned()),
            (
                "resource_type".to_owned(),
                "ThreatInsightConfiguration".to_owned(),
            ),
        ]);
        let mut conflicting_wire = first_wire.clone();
        conflicting_wire.payload =
            br#"{"action":"block","domain":"example.okta.test","exclude_zones":["zone-b"]}"#
                .to_vec();

        let first = CommittedSourceEvent::decode(&encode(first_wire))
            .unwrap()
            .unwrap();
        let conflicting = CommittedSourceEvent::decode(&encode(conflicting_wire))
            .unwrap()
            .unwrap();

        assert_ne!(first.observation_id(), conflicting.observation_id());
        assert_ne!(first.record_digest(), conflicting.record_digest());
    }

    #[test]
    fn legacy_threat_insight_requires_matching_provider_domains() {
        let mut wire = source_wire();
        wire.id = "okta-threat-insight-example.okta.test-1720000000123".to_owned();
        wire.tenant_id = "tenant-a".to_owned();
        wire.source_id = "okta".to_owned();
        wire.kind = OKTA_THREAT_INSIGHT_KIND.to_owned();
        wire.schema_ref = OKTA_THREAT_INSIGHT_SCHEMA_REF.to_owned();
        wire.payload =
            br#"{"action":"block","domain":"other.okta.test","exclude_zones":[]}"#.to_vec();
        wire.attributes = HashMap::from([
            (
                SOURCE_RUNTIME_ID_ATTRIBUTE.to_owned(),
                "okta-runtime".to_owned(),
            ),
            ("domain".to_owned(), "example.okta.test".to_owned()),
            ("family".to_owned(), "threat_insight".to_owned()),
        ]);

        assert!(matches!(
            CommittedSourceEvent::decode(&encode(wire)),
            Err(AppendLogDecodeError::InvalidModel(message))
                if message == "legacy Okta threat insight identity is inconsistent"
        ));
    }

    #[test]
    fn current_threat_insight_content_identity_is_preserved() {
        let mut wire = source_wire();
        wire.id = format!("{CURRENT_OKTA_THREAT_INSIGHT_PREFIX}{}", "a".repeat(64));
        wire.tenant_id = "example.okta.test".to_owned();
        wire.source_id = "okta".to_owned();
        wire.kind = OKTA_THREAT_INSIGHT_KIND.to_owned();
        wire.schema_ref = OKTA_THREAT_INSIGHT_SCHEMA_REF.to_owned();

        let event = CommittedSourceEvent::decode(&encode(wire))
            .unwrap()
            .unwrap();
        assert_eq!(
            event.observation_id().as_str(),
            format!("{CURRENT_OKTA_THREAT_INSIGHT_PREFIX}{}", "a".repeat(64))
        );
    }

    #[test]
    fn record_digest_excludes_only_exact_delivery_provenance() {
        let mut first_wire = source_wire();
        first_wire.attributes.insert(
            SOURCE_COLLECTION_ID_ATTRIBUTE.to_owned(),
            "collection-one".to_owned(),
        );
        let first = CommittedSourceEvent::decode(&encode(first_wire))
            .unwrap()
            .unwrap();

        let mut second_wire = source_wire();
        second_wire.attributes.insert(
            SOURCE_RUNTIME_ID_ATTRIBUTE.to_owned(),
            "box-replacement".to_owned(),
        );
        second_wire.attributes.insert(
            SOURCE_COLLECTION_ID_ATTRIBUTE.to_owned(),
            "collection-two".to_owned(),
        );
        let second = CommittedSourceEvent::decode(&encode(second_wire))
            .unwrap()
            .unwrap();

        assert_eq!(first.observation_id(), second.observation_id());
        assert_ne!(first.source_runtime_id(), second.source_runtime_id());
        assert_ne!(first.attributes(), second.attributes());
        assert_ne!(first.attributes_digest(), second.attributes_digest());
        assert_eq!(first.record_digest(), second.record_digest());

        for key in [
            "source_runtime",
            "source_runtime_id_suffix",
            "source_collection",
            "source_collection_id_suffix",
        ] {
            let mut changed = first.clone();
            changed
                .attributes
                .insert(key.to_owned(), "changed".to_owned());
            assert_ne!(
                first.record_digest(),
                changed.record_digest(),
                "non-provenance attribute {key:?} was excluded"
            );
        }
    }

    #[test]
    fn reused_current_observation_id_with_different_material_conflicts() {
        let first = CommittedSourceEvent::decode(&encode(source_wire()))
            .unwrap()
            .unwrap();
        let mut conflicting_wire = source_wire();
        conflicting_wire.payload = br#"{"id":"file-1","name":"different-board.pdf"}"#.to_vec();
        let conflicting = CommittedSourceEvent::decode(&encode(conflicting_wire))
            .unwrap()
            .unwrap();

        assert_eq!(first.observation_id(), conflicting.observation_id());
        assert_ne!(first.record_digest(), conflicting.record_digest());
    }

    #[test]
    fn every_immutable_record_field_remains_digest_bound() {
        let mut wire = source_wire();
        wire.source_id = "okta".to_owned();
        wire.kind = "okta.threat_insight".to_owned();
        wire.schema_ref = "okta/threat_insight/v1".to_owned();
        wire.payload =
            br#"{"action":"block","domain":"example.okta.test","exclude_zones":["zone-a"]}"#
                .to_vec();
        wire.attributes = HashMap::from([
            (
                SOURCE_RUNTIME_ID_ATTRIBUTE.to_owned(),
                "writer-okta".to_owned(),
            ),
            (
                SOURCE_COLLECTION_ID_ATTRIBUTE.to_owned(),
                "collection-one".to_owned(),
            ),
            ("action".to_owned(), "block".to_owned()),
            ("domain".to_owned(), "example.okta.test".to_owned()),
            ("exclude_zone_count".to_owned(), "1".to_owned()),
            ("family".to_owned(), "threat_insight".to_owned()),
            ("resource_id".to_owned(), "threat_insight_config".to_owned()),
            (
                "resource_type".to_owned(),
                "ThreatInsightConfiguration".to_owned(),
            ),
        ]);
        let original = CommittedSourceEvent::decode(&encode(wire))
            .unwrap()
            .unwrap();

        let mut changes: Vec<(&str, CommittedSourceEvent)> = Vec::new();
        let mut changed = original.clone();
        changed.tenant_id = TenantId::parse("tenant-b").unwrap();
        changes.push(("tenant_id", changed));
        let mut changed = original.clone();
        changed.observation_id = ObservationId::parse("event-2").unwrap();
        changes.push(("observation_id", changed));
        let mut changed = original.clone();
        changed.source_id = "github".to_owned();
        changes.push(("source_id", changed));
        let mut changed = original.clone();
        changed.family_id = "applications".to_owned();
        changes.push(("family_id", changed));
        let mut changed = original.clone();
        changed.event_kind = "okta.applications".to_owned();
        changes.push(("event_kind", changed));
        let mut changed = original.clone();
        changed.schema_ref = "okta/threat_insight/v2".to_owned();
        changes.push(("schema_ref", changed));
        let mut changed = original.clone();
        changed.observed_at_unix_ms += 1;
        changes.push(("observed_at", changed));
        for key in [
            "action",
            "domain",
            "exclude_zone_count",
            "family",
            "resource_id",
            "resource_type",
        ] {
            let mut changed = original.clone();
            changed
                .attributes
                .insert(key.to_owned(), format!("changed-{key}"));
            changes.push((key, changed));
        }
        let mut changed = original.clone();
        changed.payload = serde_json::json!({
            "action": "none",
            "domain": "example.okta.test",
            "exclude_zones": ["zone-a"]
        });
        changes.push(("payload", changed));

        for (field, changed) in changes {
            assert_ne!(
                original.record_digest(),
                changed.record_digest(),
                "changed {field} reused the immutable record digest"
            );
        }
    }

    #[test]
    fn direct_input_cannot_change_source_family_ownership() {
        let input = CommittedSourceInput {
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            source_runtime_id: SourceRuntimeId::parse("box-prod").unwrap(),
            observation_id: ObservationId::parse("event-1").unwrap(),
            source_id: "box".to_owned(),
            family_id: "content_assets".to_owned(),
            event_kind: "github.repositories".to_owned(),
            schema_ref: "box/content_assets/v1".to_owned(),
            observed_at_unix_ms: 1_720_000_000_123,
            attributes: BTreeMap::new(),
            payload: serde_json::json!({}),
        };
        assert!(matches!(
            CommittedSourceEvent::from_input(input),
            Err(AppendLogDecodeError::Missing(_))
        ));
    }

    #[test]
    fn decode_errors_explain_the_boundary_failure() {
        assert!(
            AppendLogDecodeError::Protobuf("bad wire".to_owned())
                .to_string()
                .contains("bad wire")
        );
        assert!(
            AppendLogDecodeError::Missing("tenant_id")
                .to_string()
                .contains("tenant_id")
        );
        assert!(
            AppendLogDecodeError::InvalidPayload("bad json".to_owned())
                .to_string()
                .contains("bad json")
        );
        assert!(
            AppendLogDecodeError::InvalidModel("bad id".to_owned())
                .to_string()
                .contains("bad id")
        );
    }
}
