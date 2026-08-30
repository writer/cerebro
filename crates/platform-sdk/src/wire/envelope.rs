//! Common external-event envelope, canonical digest, and signing material.
//!
//! Envelope validation admits bounded typed content and prepares deterministic
//! bytes. It does not authenticate the tenant or producer, verify a detached
//! signature, enforce producer sequence/chain continuity, append the event, or
//! derive tenant identity from trusted admission context.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ContentDigest, SdkError};

use super::payload::{
    AgentActivity, AgentCapability, ConnectorManifest, EndpointSessionLease, EndpointTelemetry,
    MetricSnapshot, RemediationOutcome, ScannerFinding, ThreatIntelligenceObservation,
};
use super::validation::{
    validate_attribute, validate_digest, validate_id, validate_json_bounds, validate_text,
};
use super::{
    EXTERNAL_EVENT_SCHEMA_V1, MAX_PAYLOAD_BYTES, SIGNING_DOMAIN_V1, WireContractFamily,
    WireEvidenceState,
};

/// Detached signature metadata. Key material and trust roots remain host-owned.
///
/// All fields are opaque bounded strings at the SDK layer. The trusted host must
/// select an allowed algorithm, resolve `key_id` without exposing key material,
/// decode `value`, and verify it over [`ExternalEventEnvelope::signing_bytes`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireSignature {
    /// Host-defined signature algorithm identifier.
    pub algorithm: String,
    /// Non-secret reference to the verification key.
    pub key_id: String,
    /// Host-defined encoded signature value.
    pub value: String,
}

/// One versioned record from an external producer.
///
/// String identities use the portable wire alphabet rather than trusted domain
/// types. In particular, `tenant_id` remains a producer claim until the admission
/// host compares it with authenticated context. Unknown fields are rejected.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEventEnvelope {
    /// Exact common-envelope schema, currently [`EXTERNAL_EVENT_SCHEMA_V1`].
    pub schema_version: String,
    /// Closed payload family used for typed decoding.
    pub contract_family: WireContractFamily,
    /// Exact schema required by [`WireContractFamily::schema_ref`].
    pub payload_schema_ref: String,
    /// Stable producer event identity used for replay and collision checks.
    pub event_id: String,
    /// Producer-asserted tenant identity; never the source of admission tenancy.
    pub tenant_id: String,
    /// Stable identity of the logical producer.
    pub producer_id: String,
    /// Stable identity of the concrete producer instance or run.
    pub producer_instance_id: String,
    /// Stable identity of the primary object described by the payload.
    pub subject_id: String,
    /// Non-zero producer sequence used by host-owned ordering admission.
    pub sequence: u64,
    /// Non-zero Unix-millisecond source event time.
    pub occurred_at_unix_ms: u64,
    /// Unix-millisecond observation time, no earlier than occurrence.
    pub observed_at_unix_ms: u64,
    /// Producer-claimed completeness and freshness, conservative when omitted.
    #[serde(default)]
    pub evidence: WireEvidenceState,
    /// Family-specific JSON value decoded only after common bounds pass.
    pub payload: Value,
    /// Closed, non-secret operational metadata map in lexical key order.
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    /// Optional predecessor digest for host-owned producer-chain validation.
    pub previous_event_digest: Option<String>,
    /// Optional detached signature metadata; cryptographic verification is external.
    pub signature: Option<WireSignature>,
}

/// Domain-separated signing record containing an unsigned envelope.
///
/// Algorithm and key ID are signed explicitly to prevent metadata substitution.
#[derive(Serialize)]
struct SigningRecord<'a> {
    domain: &'static str,
    algorithm: &'a str,
    key_id: &'a str,
    envelope: &'a ExternalEventEnvelope,
}

impl ExternalEventEnvelope {
    /// Validates the envelope and its family-specific payload.
    ///
    /// Validation requires exact common and family schema versions; bounded
    /// identifiers; non-zero, ordered occurrence/observation times; allowlisted
    /// non-secret attributes; digest-shaped chain metadata; bounded signature
    /// metadata; a payload no larger than 256 KiB with bounded depth and nodes;
    /// strict typed decoding; and family-specific payload invariants.
    ///
    /// The returned typed payload is decoded from a clone, leaving the envelope
    /// unchanged. This method does not verify the signature, compare sequence or
    /// predecessor with durable producer state, authenticate any identity, check
    /// timestamps against a trusted clock, or append the event.
    ///
    /// # Errors
    ///
    /// Returns the first common-field, resource-bound, typed-decoding, or payload
    /// validation error, and [`SdkError::Backend`] if payload JSON serialization
    /// fails during aggregate byte measurement.
    pub fn validate(&self) -> Result<DecodedWirePayload, SdkError> {
        if self.schema_version != EXTERNAL_EVENT_SCHEMA_V1 {
            return Err(SdkError::Invalid("external event schema version"));
        }
        if self.payload_schema_ref != self.contract_family.schema_ref() {
            return Err(SdkError::Invalid("external event payload schema"));
        }
        for (field, value) in [
            ("external event id", self.event_id.as_str()),
            ("external tenant id", self.tenant_id.as_str()),
            ("external producer id", self.producer_id.as_str()),
            (
                "external producer instance id",
                self.producer_instance_id.as_str(),
            ),
            ("external subject id", self.subject_id.as_str()),
        ] {
            validate_id(value, field)?;
        }
        if self.sequence == 0 {
            return Err(SdkError::OutOfRange("external event sequence"));
        }
        if self.occurred_at_unix_ms == 0 || self.observed_at_unix_ms < self.occurred_at_unix_ms {
            return Err(SdkError::OutOfRange("external event observation time"));
        }
        if self.attributes.len() > super::EXTERNAL_EVENT_ATTRIBUTE_KEYS.len() {
            return Err(SdkError::OutOfRange("external event attributes"));
        }
        for (key, value) in &self.attributes {
            validate_attribute(key, value)?;
        }
        if let Some(digest) = self.previous_event_digest.as_deref() {
            validate_digest(digest, "external previous event digest")?;
        }
        if let Some(signature) = self.signature.as_ref() {
            validate_id(&signature.algorithm, "external signature algorithm")?;
            validate_id(&signature.key_id, "external signature key id")?;
            validate_text(&signature.value, "external signature value")?;
        }

        // Measure compact serialized payload bytes independently from recursive
        // node/depth checks; neither bound substitutes for the other.
        let encoded = serde_json::to_vec(&self.payload)
            .map_err(|error| SdkError::Backend(format!("payload serialization failed: {error}")))?;
        if encoded.len() > MAX_PAYLOAD_BYTES {
            return Err(SdkError::TooLong("external event payload"));
        }
        let mut nodes = 0;
        validate_json_bounds(&self.payload, 0, &mut nodes)?;

        let decoded = DecodedWirePayload::decode(self.contract_family, self.payload.clone())?;
        decoded.validate(self.evidence)?;
        Ok(decoded)
    }

    /// Returns RFC 8785 canonical JSON for durable digesting.
    ///
    /// The signature field is included. This method does not call [`Self::validate`],
    /// so canonical bytes for a malformed envelope are not admission evidence.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Backend`] if JCS canonicalization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SdkError> {
        serde_jcs::to_vec(self).map_err(|error| {
            SdkError::Backend(format!("external event canonicalization failed: {error}"))
        })
    }

    /// Returns the canonical digest of the entire envelope.
    ///
    /// Because the detached signature metadata is included, adding or changing a
    /// signature changes this digest. Call [`Self::signing_bytes`] for the stable
    /// unsigned material used by cryptographic signing and verification.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Backend`] if canonicalization fails.
    pub fn digest(&self) -> Result<ContentDigest, SdkError> {
        Ok(ContentDigest::of_bytes(self.canonical_bytes()?))
    }

    /// Returns domain-separated canonical bytes with the signature removed.
    ///
    /// `algorithm` and `key_id` are validated and included outside the unsigned
    /// envelope in the signed record. They are method inputs and are not required
    /// to equal metadata currently stored in [`Self::signature`]; signing and
    /// verification hosts must pass the exact metadata they intend to bind. This
    /// method does not validate the envelope or perform cryptography.
    ///
    /// # Errors
    ///
    /// Returns identifier validation errors or [`SdkError::Backend`] if JCS
    /// canonicalization fails.
    pub fn signing_bytes(&self, algorithm: &str, key_id: &str) -> Result<Vec<u8>, SdkError> {
        validate_id(algorithm, "external signature algorithm")?;
        validate_id(key_id, "external signature key id")?;
        let mut unsigned = self.clone();

        // Remove all signature metadata before wrapping the envelope with the
        // domain, algorithm, and key identity that are themselves signed.
        unsigned.signature = None;
        serde_jcs::to_vec(&SigningRecord {
            domain: SIGNING_DOMAIN_V1,
            algorithm,
            key_id,
            envelope: &unsigned,
        })
        .map_err(|error| SdkError::Backend(format!("external signing material failed: {error}")))
    }
}

/// Typed payload returned only after family and schema matching.
///
/// Construction through [`ExternalEventEnvelope::validate`] also applies common
/// JSON resource bounds and each payload's semantic validator.
#[derive(Clone, Debug, PartialEq)]
pub enum DecodedWirePayload {
    /// Validated agent-activity payload.
    AgentActivity(AgentActivity),
    /// Validated endpoint-telemetry payload.
    EndpointTelemetry(EndpointTelemetry),
    /// Validated endpoint session-lease payload.
    EndpointSessionLease(EndpointSessionLease),
    /// Validated threat-intelligence observation.
    ThreatIntelligence(ThreatIntelligenceObservation),
    /// Validated remediation outcome.
    RemediationOutcome(RemediationOutcome),
    /// Validated metric snapshot.
    MetricSnapshot(MetricSnapshot),
    /// Validated scanner finding.
    ScannerFinding(ScannerFinding),
    /// Validated connector manifest.
    ConnectorManifest(ConnectorManifest),
    /// Validated agent capability advertisement.
    AgentCapability(AgentCapability),
}

impl DecodedWirePayload {
    /// Strictly decodes a JSON value as the selected closed payload family.
    ///
    /// Detailed Serde failures are collapsed to one invalid-payload category so
    /// producer-controlled content is not reflected in the public error.
    fn decode(family: WireContractFamily, payload: Value) -> Result<Self, SdkError> {
        macro_rules! decode {
            ($variant:ident, $kind:ty) => {
                serde_json::from_value::<$kind>(payload)
                    .map(Self::$variant)
                    .map_err(|_| SdkError::Invalid("external event payload"))
            };
        }
        match family {
            WireContractFamily::AgentActivity => decode!(AgentActivity, AgentActivity),
            WireContractFamily::EndpointTelemetry => {
                decode!(EndpointTelemetry, EndpointTelemetry)
            }
            WireContractFamily::EndpointSessionLease => {
                decode!(EndpointSessionLease, EndpointSessionLease)
            }
            WireContractFamily::ThreatIntelligence => {
                decode!(ThreatIntelligence, ThreatIntelligenceObservation)
            }
            WireContractFamily::RemediationOutcome => {
                decode!(RemediationOutcome, RemediationOutcome)
            }
            WireContractFamily::MetricSnapshot => decode!(MetricSnapshot, MetricSnapshot),
            WireContractFamily::ScannerFinding => decode!(ScannerFinding, ScannerFinding),
            WireContractFamily::ConnectorManifest => {
                decode!(ConnectorManifest, ConnectorManifest)
            }
            WireContractFamily::AgentCapability => decode!(AgentCapability, AgentCapability),
        }
    }

    /// Dispatches family-specific semantic validation.
    ///
    /// Endpoint telemetry and metric snapshots consume the envelope evidence
    /// state directly for fail-closed policy. Other families still carry that
    /// state in the envelope, but their current shape validators do not branch on it.
    fn validate(&self, evidence: WireEvidenceState) -> Result<(), SdkError> {
        match self {
            Self::AgentActivity(value) => value.validate(),
            Self::EndpointTelemetry(value) => value.validate(evidence),
            Self::EndpointSessionLease(value) => value.validate(),
            Self::ThreatIntelligence(value) => value.validate(),
            Self::RemediationOutcome(value) => value.validate(),
            Self::MetricSnapshot(value) => value.validate(evidence),
            Self::ScannerFinding(value) => value.validate(),
            Self::ConnectorManifest(value) => value.validate(),
            Self::AgentCapability(value) => value.validate(),
        }
    }
}
