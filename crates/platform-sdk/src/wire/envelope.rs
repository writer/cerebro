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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireSignature {
    pub algorithm: String,
    pub key_id: String,
    pub value: String,
}

/// One versioned record from an external producer.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEventEnvelope {
    pub schema_version: String,
    pub contract_family: WireContractFamily,
    pub payload_schema_ref: String,
    pub event_id: String,
    pub tenant_id: String,
    pub producer_id: String,
    pub producer_instance_id: String,
    pub subject_id: String,
    pub sequence: u64,
    pub occurred_at_unix_ms: u64,
    pub observed_at_unix_ms: u64,
    #[serde(default)]
    pub evidence: WireEvidenceState,
    pub payload: Value,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    pub previous_event_digest: Option<String>,
    pub signature: Option<WireSignature>,
}

#[derive(Serialize)]
struct SigningRecord<'a> {
    domain: &'static str,
    algorithm: &'a str,
    key_id: &'a str,
    envelope: &'a ExternalEventEnvelope,
}

impl ExternalEventEnvelope {
    /// Validates the envelope and its family-specific payload.
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
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SdkError> {
        serde_jcs::to_vec(self).map_err(|error| {
            SdkError::Backend(format!("external event canonicalization failed: {error}"))
        })
    }

    /// Returns the canonical digest of the entire envelope.
    pub fn digest(&self) -> Result<ContentDigest, SdkError> {
        Ok(ContentDigest::of_bytes(self.canonical_bytes()?))
    }

    /// Returns domain-separated canonical bytes with the signature removed.
    pub fn signing_bytes(&self, algorithm: &str, key_id: &str) -> Result<Vec<u8>, SdkError> {
        validate_id(algorithm, "external signature algorithm")?;
        validate_id(key_id, "external signature key id")?;
        let mut unsigned = self.clone();
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
#[derive(Clone, Debug, PartialEq)]
pub enum DecodedWirePayload {
    AgentActivity(AgentActivity),
    EndpointTelemetry(EndpointTelemetry),
    EndpointSessionLease(EndpointSessionLease),
    ThreatIntelligence(ThreatIntelligenceObservation),
    RemediationOutcome(RemediationOutcome),
    MetricSnapshot(MetricSnapshot),
    ScannerFinding(ScannerFinding),
    ConnectorManifest(ConnectorManifest),
    AgentCapability(AgentCapability),
}

impl DecodedWirePayload {
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
