use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ActionState, ContentDigest, SdkError};

/// Version of the common external-event envelope.
pub const EXTERNAL_EVENT_SCHEMA_V1: &str = "cerebro.external-event/v1";
/// Agent activity payload schema.
pub const AGENT_ACTIVITY_SCHEMA_V1: &str = "cerebro/agent/activity/v1";
/// Endpoint telemetry payload schema.
pub const ENDPOINT_TELEMETRY_SCHEMA_V1: &str = "cerebro/endpoint/telemetry/v1";
/// Endpoint session-lease payload schema.
pub const ENDPOINT_SESSION_LEASE_SCHEMA_V1: &str = "cerebro/endpoint/session-lease/v1";
/// Threat-intelligence payload schema.
pub const THREAT_INTELLIGENCE_SCHEMA_V1: &str = "cerebro/threat-intelligence/observation/v1";
/// Remediation outcome payload schema.
pub const REMEDIATION_OUTCOME_SCHEMA_V1: &str = "cerebro/remediation/outcome/v1";
/// Metric snapshot payload schema.
pub const METRIC_SNAPSHOT_SCHEMA_V1: &str = "cerebro/metric/snapshot/v1";
/// Scanner finding payload schema.
pub const SCANNER_FINDING_SCHEMA_V1: &str = "cerebro/scanner/finding/v1";
/// Declarative connector-manifest payload schema.
pub const CONNECTOR_MANIFEST_SCHEMA_V1: &str = "cerebro/connector/manifest/v1";
/// Agent capability payload schema.
pub const AGENT_CAPABILITY_SCHEMA_V1: &str = "cerebro/agent/capability/v1";

const SIGNING_DOMAIN_V1: &str = "cerebro.external-event-signature/v1";
const MAX_ID_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 1_024;
const MAX_PAYLOAD_BYTES: usize = 256 * 1_024;
const MAX_PAYLOAD_DEPTH: usize = 32;
const MAX_PAYLOAD_NODES: usize = 8_192;
const MAX_REFS: usize = 512;
const MAX_SESSION_LEASE_MS: u64 = 60 * 60 * 1_000;

/// Closed set of portable payload families admitted through the common wire.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireContractFamily {
    AgentActivity,
    EndpointTelemetry,
    EndpointSessionLease,
    ThreatIntelligence,
    RemediationOutcome,
    MetricSnapshot,
    ScannerFinding,
    ConnectorManifest,
    AgentCapability,
}

impl WireContractFamily {
    /// Returns the only payload schema admitted for this family in v1.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::AgentActivity => AGENT_ACTIVITY_SCHEMA_V1,
            Self::EndpointTelemetry => ENDPOINT_TELEMETRY_SCHEMA_V1,
            Self::EndpointSessionLease => ENDPOINT_SESSION_LEASE_SCHEMA_V1,
            Self::ThreatIntelligence => THREAT_INTELLIGENCE_SCHEMA_V1,
            Self::RemediationOutcome => REMEDIATION_OUTCOME_SCHEMA_V1,
            Self::MetricSnapshot => METRIC_SNAPSHOT_SCHEMA_V1,
            Self::ScannerFinding => SCANNER_FINDING_SCHEMA_V1,
            Self::ConnectorManifest => CONNECTOR_MANIFEST_SCHEMA_V1,
            Self::AgentCapability => AGENT_CAPABILITY_SCHEMA_V1,
        }
    }
}

/// Whether the producer observed its complete declared population.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCompleteness {
    Complete,
    Partial,
    Truncated,
}

/// Whether the observation is current enough for the declared decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFreshness {
    Fresh,
    Stale,
    Unknown,
}

/// Fail-closed evidence quality carried by every external producer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WireEvidenceState {
    pub completeness: EvidenceCompleteness,
    pub freshness: EvidenceFreshness,
}

impl Default for WireEvidenceState {
    fn default() -> Self {
        Self {
            completeness: EvidenceCompleteness::Partial,
            freshness: EvidenceFreshness::Unknown,
        }
    }
}

impl WireEvidenceState {
    /// Returns true only for fresh evidence over a complete population.
    pub const fn supports_authoritative_decision(self) -> bool {
        matches!(self.completeness, EvidenceCompleteness::Complete)
            && matches!(self.freshness, EvidenceFreshness::Fresh)
    }
}

/// Detached signature metadata. Key material and trust roots remain host-owned.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
        if self.attributes.len() > 64 {
            return Err(SdkError::OutOfRange("external event attributes"));
        }
        for (key, value) in &self.attributes {
            validate_id(key, "external event attribute key")?;
            validate_text(value, "external event attribute value")?;
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActivity {
    pub session_id: String,
    pub agent_id: String,
    pub device_id: Option<String>,
    pub action: String,
    pub resource_ref: String,
    pub policy_revision: String,
    pub input_digest: String,
    pub outcome_digest: Option<String>,
}

impl AgentActivity {
    fn validate(&self) -> Result<(), SdkError> {
        for (field, value) in [
            ("agent activity session id", self.session_id.as_str()),
            ("agent activity agent id", self.agent_id.as_str()),
            ("agent activity action", self.action.as_str()),
            ("agent activity resource ref", self.resource_ref.as_str()),
            (
                "agent activity policy revision",
                self.policy_revision.as_str(),
            ),
        ] {
            validate_id(value, field)?;
        }
        if let Some(device_id) = self.device_id.as_deref() {
            validate_id(device_id, "agent activity device id")?;
        }
        validate_digest(&self.input_digest, "agent activity input digest")?;
        if let Some(digest) = self.outcome_digest.as_deref() {
            validate_digest(digest, "agent activity outcome digest")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointTelemetry {
    pub endpoint_id: String,
    pub agent_id: String,
    pub observation_kind: String,
    pub collector: String,
    pub privacy_class: String,
    pub truncated: bool,
    pub content_digest: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

impl EndpointTelemetry {
    fn validate(&self, evidence: WireEvidenceState) -> Result<(), SdkError> {
        for (field, value) in [
            ("endpoint id", self.endpoint_id.as_str()),
            ("endpoint agent id", self.agent_id.as_str()),
            ("endpoint observation kind", self.observation_kind.as_str()),
            ("endpoint collector", self.collector.as_str()),
            ("endpoint privacy class", self.privacy_class.as_str()),
        ] {
            validate_id(value, field)?;
        }
        validate_digest(&self.content_digest, "endpoint content digest")?;
        validate_refs(&self.evidence_refs, "endpoint evidence ref")?;
        if self.truncated && matches!(evidence.completeness, EvidenceCompleteness::Complete) {
            return Err(SdkError::Conflict(
                "truncated endpoint telemetry cannot claim complete evidence".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointOwnership {
    OrganizationOwned,
    BringYourOwnDevice,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointNetworkProfile {
    Isolated,
    ProviderOnly,
    BuildOnly,
    BreakGlass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointSessionLease {
    pub lease_id: String,
    pub agent_id: String,
    pub user_subject: String,
    pub session_id: String,
    pub operation: String,
    pub repository_ref: String,
    pub repository_revision: Option<String>,
    pub endpoint_ownership: EndpointOwnership,
    pub network_profile: EndpointNetworkProfile,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub policy_id: String,
    pub policy_revision: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub revocation_epoch: u64,
    #[serde(default)]
    pub audience: Vec<String>,
    #[serde(default)]
    pub posture_source_refs: Vec<String>,
}

impl EndpointSessionLease {
    fn validate(&self) -> Result<(), SdkError> {
        for (field, value) in [
            ("endpoint lease id", self.lease_id.as_str()),
            ("endpoint lease agent id", self.agent_id.as_str()),
            ("endpoint lease user subject", self.user_subject.as_str()),
            ("endpoint lease session id", self.session_id.as_str()),
            ("endpoint lease operation", self.operation.as_str()),
            (
                "endpoint lease repository ref",
                self.repository_ref.as_str(),
            ),
            ("endpoint lease policy id", self.policy_id.as_str()),
            (
                "endpoint lease policy revision",
                self.policy_revision.as_str(),
            ),
        ] {
            validate_id(value, field)?;
        }
        if let Some(revision) = self.repository_revision.as_deref() {
            validate_id(revision, "endpoint lease repository revision")?;
        }
        if self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > MAX_SESSION_LEASE_MS
        {
            return Err(SdkError::OutOfRange("endpoint lease validity"));
        }
        validate_refs(&self.capabilities, "endpoint lease capability")?;
        validate_refs(&self.audience, "endpoint lease audience")?;
        validate_refs(&self.posture_source_refs, "endpoint posture source ref")?;
        if self.capabilities.is_empty() || self.audience.is_empty() {
            return Err(SdkError::Empty("endpoint lease capability or audience"));
        }
        Ok(())
    }

    /// Returns whether the lease is active at the supplied time and revocation epoch.
    pub fn is_active_at(&self, now_unix_ms: u64, current_revocation_epoch: u64) -> bool {
        self.validate().is_ok()
            && now_unix_ms >= self.issued_at_unix_ms
            && now_unix_ms < self.expires_at_unix_ms
            && self.revocation_epoch == current_revocation_epoch
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatIndicatorKind {
    Domain,
    IpAddress,
    Url,
    FileHash,
    EmailAddress,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatVerdict {
    Unknown,
    Benign,
    Suspicious,
    Malicious,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatPromotionReason {
    InternalObservation,
    MultiSourceCorroboration,
    NotPromoted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatIntelligenceObservation {
    pub indicator_id: String,
    pub indicator_kind: ThreatIndicatorKind,
    pub normalized_value: String,
    pub verdict: ThreatVerdict,
    pub score_basis_points: u16,
    pub confidence_basis_points: u16,
    pub source_count: u16,
    pub internal_observation_count: u64,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    #[serde(default)]
    pub source_event_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub promotion_reason: ThreatPromotionReason,
}

impl ThreatIntelligenceObservation {
    fn validate(&self) -> Result<(), SdkError> {
        validate_id(&self.indicator_id, "threat indicator id")?;
        validate_text(&self.normalized_value, "threat normalized value")?;
        if self.score_basis_points > 10_000 || self.confidence_basis_points > 10_000 {
            return Err(SdkError::OutOfRange("threat score"));
        }
        if self.source_count == 0 || self.internal_observation_count > u64::from(self.source_count)
        {
            return Err(SdkError::OutOfRange("threat source count"));
        }
        if self.first_seen_unix_ms == 0
            || self.last_seen_unix_ms < self.first_seen_unix_ms
            || self.valid_until_unix_ms <= self.last_seen_unix_ms
        {
            return Err(SdkError::OutOfRange("threat observation time"));
        }
        validate_refs(&self.source_event_refs, "threat source event ref")?;
        validate_refs(&self.evidence_refs, "threat evidence ref")?;
        Ok(())
    }

    /// Returns whether the observation may enter the canonical graph candidate path.
    pub fn supports_promotion(&self, evidence: WireEvidenceState, now_unix_ms: u64) -> bool {
        if self.validate().is_err()
            || !evidence.supports_authoritative_decision()
            || now_unix_ms >= self.valid_until_unix_ms
            || !matches!(self.verdict, ThreatVerdict::Malicious)
            || self.source_event_refs.is_empty()
            || self.evidence_refs.is_empty()
        {
            return false;
        }
        match self.promotion_reason {
            ThreatPromotionReason::InternalObservation => self.internal_observation_count > 0,
            ThreatPromotionReason::MultiSourceCorroboration => {
                self.source_count >= 2 && self.source_event_refs.len() >= 2
            }
            ThreatPromotionReason::NotPromoted => false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationOutcome {
    pub operation_id: String,
    pub finding_id: String,
    pub action_kind: String,
    pub target_id: String,
    pub state: ActionState,
    pub idempotency_key: String,
    pub proposal_digest: String,
    pub provider_receipt_digest: Option<String>,
    pub verification_receipt_digest: Option<String>,
}

impl RemediationOutcome {
    fn validate(&self) -> Result<(), SdkError> {
        for (field, value) in [
            ("remediation operation id", self.operation_id.as_str()),
            ("remediation finding id", self.finding_id.as_str()),
            ("remediation action kind", self.action_kind.as_str()),
            ("remediation target id", self.target_id.as_str()),
            ("remediation idempotency key", self.idempotency_key.as_str()),
        ] {
            validate_id(value, field)?;
        }
        validate_digest(&self.proposal_digest, "remediation proposal digest")?;
        for digest in [
            self.provider_receipt_digest.as_deref(),
            self.verification_receipt_digest.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_digest(digest, "remediation receipt digest")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricSnapshot {
    pub metric_id: String,
    pub definition_version: u64,
    pub observed_at_unix_ms: u64,
    pub value_microunits: i64,
    pub unit: String,
    pub truncated: bool,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub snapshot_digest: String,
}

impl MetricSnapshot {
    fn validate(&self, evidence: WireEvidenceState) -> Result<(), SdkError> {
        validate_id(&self.metric_id, "metric id")?;
        validate_id(&self.unit, "metric unit")?;
        validate_digest(&self.snapshot_digest, "metric snapshot digest")?;
        validate_refs(&self.evidence_refs, "metric evidence ref")?;
        if self.definition_version == 0 || self.observed_at_unix_ms == 0 {
            return Err(SdkError::OutOfRange("metric snapshot version or time"));
        }
        if self.truncated && matches!(evidence.completeness, EvidenceCompleteness::Complete) {
            return Err(SdkError::Conflict(
                "truncated metric snapshot cannot claim complete evidence".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns true only when the metric may be represented as verified.
    pub fn is_verified(&self, evidence: WireEvidenceState) -> bool {
        self.validate(evidence).is_ok()
            && evidence.supports_authoritative_decision()
            && !self.truncated
            && !self.evidence_refs.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerValidationState {
    Validated,
    NeedsReview,
    Suppressed,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerFinding {
    pub finding_id: String,
    pub scanner_id: String,
    pub rule_id: String,
    pub rule_version: String,
    pub severity: ScannerSeverity,
    pub validation_state: ScannerValidationState,
    pub subject_ref: String,
    pub source_revision: String,
    pub location_ref: Option<String>,
    pub evidence_digest: String,
    pub evidence_ref: Option<String>,
    pub fixed_version: Option<String>,
}

impl ScannerFinding {
    fn validate(&self) -> Result<(), SdkError> {
        for (field, value) in [
            ("scanner finding id", self.finding_id.as_str()),
            ("scanner id", self.scanner_id.as_str()),
            ("scanner rule id", self.rule_id.as_str()),
            ("scanner rule version", self.rule_version.as_str()),
            ("scanner subject ref", self.subject_ref.as_str()),
            ("scanner source revision", self.source_revision.as_str()),
        ] {
            validate_id(value, field)?;
        }
        validate_digest(&self.evidence_digest, "scanner evidence digest")?;
        for value in [
            self.location_ref.as_deref(),
            self.evidence_ref.as_deref(),
            self.fixed_version.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_text(value, "scanner optional text")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorManifest {
    pub connector_id: String,
    pub manifest_version: u64,
    pub auth_kind: String,
    #[serde(default)]
    pub object_kinds: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub input_digest: String,
    pub compiled_digest: String,
    pub compiled_at_unix_ms: u64,
}

impl ConnectorManifest {
    fn validate(&self) -> Result<(), SdkError> {
        validate_id(&self.connector_id, "connector id")?;
        validate_id(&self.auth_kind, "connector auth kind")?;
        validate_refs(&self.object_kinds, "connector object kind")?;
        validate_refs(&self.capabilities, "connector capability")?;
        validate_digest(&self.input_digest, "connector input digest")?;
        validate_digest(&self.compiled_digest, "connector compiled digest")?;
        if self.manifest_version == 0
            || self.compiled_at_unix_ms == 0
            || self.object_kinds.is_empty()
        {
            return Err(SdkError::OutOfRange(
                "connector manifest version, time, or objects",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCapability {
    pub agent_id: String,
    pub capability_id: String,
    #[serde(default)]
    pub tool_ids: Vec<String>,
    pub maximum_action_stage: AgentActionStage,
    #[serde(default)]
    pub evidence_source_refs: Vec<String>,
    pub definition_digest: String,
}

impl AgentCapability {
    fn validate(&self) -> Result<(), SdkError> {
        validate_id(&self.agent_id, "capability agent id")?;
        validate_id(&self.capability_id, "capability id")?;
        validate_refs(&self.tool_ids, "capability tool id")?;
        validate_refs(&self.evidence_source_refs, "capability evidence source ref")?;
        validate_digest(&self.definition_digest, "capability definition digest")?;
        if self.tool_ids.is_empty() || self.evidence_source_refs.is_empty() {
            return Err(SdkError::Empty("capability tools or evidence sources"));
        }
        Ok(())
    }
}

/// Highest authority stage an advertised agent capability can request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentActionStage {
    Observe,
    Recommend,
    Propose,
    Execute,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireIngestOutcome {
    Accepted,
    Duplicate,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireIngestReason {
    Accepted,
    EventAlreadyAccepted,
    EventIdCollision,
    UnsupportedSchema,
    InvalidEnvelope,
    InvalidPayload,
    SignatureVerificationFailed,
    UnsafePayload,
    SequenceGapOrReordering,
    EventChainMismatch,
    PersistenceUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireIngestReceipt {
    pub event_id: String,
    pub event_digest: Option<String>,
    pub outcome: WireIngestOutcome,
    pub reason: WireIngestReason,
    pub received_at_unix_ms: u64,
}

impl WireIngestReceipt {
    /// Validates receipt consistency without claiming persistence or signature authority.
    pub fn validate(&self) -> Result<(), SdkError> {
        validate_id(&self.event_id, "wire receipt event id")?;
        if self.received_at_unix_ms == 0 {
            return Err(SdkError::OutOfRange("wire receipt time"));
        }
        if let Some(digest) = self.event_digest.as_deref() {
            validate_digest(digest, "wire receipt event digest")?;
        }
        match (self.outcome, self.reason, self.event_digest.is_some()) {
            (WireIngestOutcome::Accepted, WireIngestReason::Accepted, true)
            | (WireIngestOutcome::Duplicate, WireIngestReason::EventAlreadyAccepted, true)
            | (WireIngestOutcome::Rejected, _, _) => Ok(()),
            _ => Err(SdkError::Invalid("wire receipt outcome")),
        }
    }
}

fn validate_id(value: &str, field: &'static str) -> Result<(), SdkError> {
    if value.is_empty() {
        return Err(SdkError::Empty(field));
    }
    if value.trim() != value
        || value.len() > MAX_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/@%".contains(&byte))
    {
        return Err(SdkError::Invalid(field));
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), SdkError> {
    if value.trim().is_empty() {
        return Err(SdkError::Empty(field));
    }
    if value.trim() != value || value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control)
    {
        return Err(SdkError::Invalid(field));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), SdkError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SdkError::Invalid(field));
    }
    Ok(())
}

fn validate_refs(values: &[String], field: &'static str) -> Result<(), SdkError> {
    if values.len() > MAX_REFS {
        return Err(SdkError::OutOfRange(field));
    }
    for value in values {
        validate_id(value, field)?;
    }
    Ok(())
}

fn validate_json_bounds(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), SdkError> {
    if depth > MAX_PAYLOAD_DEPTH {
        return Err(SdkError::OutOfRange("external payload depth"));
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_PAYLOAD_NODES {
        return Err(SdkError::OutOfRange("external payload node count"));
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                validate_text(key, "external payload key")?;
                validate_json_bounds(child, depth + 1, nodes)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_json_bounds(child, depth + 1, nodes)?;
            }
        }
        Value::String(text) if text.len() > MAX_PAYLOAD_BYTES => {
            return Err(SdkError::TooLong("external payload text"));
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn evidence() -> WireEvidenceState {
        WireEvidenceState {
            completeness: EvidenceCompleteness::Complete,
            freshness: EvidenceFreshness::Fresh,
        }
    }

    fn envelope(family: WireContractFamily, payload: Value) -> ExternalEventEnvelope {
        ExternalEventEnvelope {
            schema_version: EXTERNAL_EVENT_SCHEMA_V1.to_owned(),
            contract_family: family,
            payload_schema_ref: family.schema_ref().to_owned(),
            event_id: "event-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            producer_id: "producer-1".to_owned(),
            producer_instance_id: "instance-1".to_owned(),
            subject_id: "subject-1".to_owned(),
            sequence: 1,
            occurred_at_unix_ms: 1_000,
            observed_at_unix_ms: 1_001,
            evidence: evidence(),
            payload,
            attributes: BTreeMap::new(),
            previous_event_digest: None,
            signature: None,
        }
    }

    fn sample_payloads() -> Vec<(WireContractFamily, Value)> {
        vec![
            (
                WireContractFamily::AgentActivity,
                serde_json::to_value(AgentActivity {
                    session_id: "session-1".into(),
                    agent_id: "agent-1".into(),
                    device_id: Some("device-1".into()),
                    action: "repository.read".into(),
                    resource_ref: "repository:example".into(),
                    policy_revision: "policy-1".into(),
                    input_digest: digest('a'),
                    outcome_digest: Some(digest('b')),
                })
                .unwrap(),
            ),
            (
                WireContractFamily::EndpointTelemetry,
                serde_json::to_value(EndpointTelemetry {
                    endpoint_id: "endpoint-1".into(),
                    agent_id: "agent-1".into(),
                    observation_kind: "posture".into(),
                    collector: "collector-1".into(),
                    privacy_class: "operational_metadata".into(),
                    truncated: false,
                    content_digest: digest('c'),
                    evidence_refs: vec!["evidence:1".into()],
                })
                .unwrap(),
            ),
            (
                WireContractFamily::EndpointSessionLease,
                serde_json::to_value(EndpointSessionLease {
                    lease_id: "lease-1".into(),
                    agent_id: "agent-1".into(),
                    user_subject: "user:1".into(),
                    session_id: "session-1".into(),
                    operation: "repository.read".into(),
                    repository_ref: "repository:example".into(),
                    repository_revision: Some("abc123".into()),
                    endpoint_ownership: EndpointOwnership::OrganizationOwned,
                    network_profile: EndpointNetworkProfile::ProviderOnly,
                    capabilities: vec!["repository.read".into()],
                    policy_id: "policy-1".into(),
                    policy_revision: "revision-1".into(),
                    issued_at_unix_ms: 1_000,
                    expires_at_unix_ms: 2_000,
                    revocation_epoch: 3,
                    audience: vec!["repository-broker".into()],
                    posture_source_refs: vec!["source:endpoint".into()],
                })
                .unwrap(),
            ),
            (
                WireContractFamily::ThreatIntelligence,
                serde_json::to_value(ThreatIntelligenceObservation {
                    indicator_id: "indicator-1".into(),
                    indicator_kind: ThreatIndicatorKind::Domain,
                    normalized_value: "malicious.example".into(),
                    verdict: ThreatVerdict::Malicious,
                    score_basis_points: 8_000,
                    confidence_basis_points: 9_000,
                    source_count: 2,
                    internal_observation_count: 0,
                    first_seen_unix_ms: 1_000,
                    last_seen_unix_ms: 2_000,
                    valid_until_unix_ms: 3_000,
                    source_event_refs: vec!["event:1".into(), "event:2".into()],
                    evidence_refs: vec!["evidence:1".into()],
                    promotion_reason: ThreatPromotionReason::MultiSourceCorroboration,
                })
                .unwrap(),
            ),
            (
                WireContractFamily::RemediationOutcome,
                serde_json::to_value(RemediationOutcome {
                    operation_id: "operation-1".into(),
                    finding_id: "finding-1".into(),
                    action_kind: "package.update".into(),
                    target_id: "endpoint-1".into(),
                    state: ActionState::Verified,
                    idempotency_key: "idempotency-1".into(),
                    proposal_digest: digest('d'),
                    provider_receipt_digest: Some(digest('e')),
                    verification_receipt_digest: Some(digest('f')),
                })
                .unwrap(),
            ),
            (
                WireContractFamily::MetricSnapshot,
                serde_json::to_value(MetricSnapshot {
                    metric_id: "metric-1".into(),
                    definition_version: 1,
                    observed_at_unix_ms: 2_000,
                    value_microunits: 500_000,
                    unit: "ratio".into(),
                    truncated: false,
                    evidence_refs: vec!["evidence:1".into()],
                    snapshot_digest: digest('1'),
                })
                .unwrap(),
            ),
            (
                WireContractFamily::ScannerFinding,
                serde_json::to_value(ScannerFinding {
                    finding_id: "finding-1".into(),
                    scanner_id: "scanner-1".into(),
                    rule_id: "rule-1".into(),
                    rule_version: "1".into(),
                    severity: ScannerSeverity::High,
                    validation_state: ScannerValidationState::Validated,
                    subject_ref: "repository:example".into(),
                    source_revision: "abc123".into(),
                    location_ref: Some("src/lib.rs:10".into()),
                    evidence_digest: digest('2'),
                    evidence_ref: Some("evidence:1".into()),
                    fixed_version: None,
                })
                .unwrap(),
            ),
            (
                WireContractFamily::ConnectorManifest,
                serde_json::to_value(ConnectorManifest {
                    connector_id: "connector-1".into(),
                    manifest_version: 1,
                    auth_kind: "oauth2".into(),
                    object_kinds: vec!["user".into()],
                    capabilities: vec!["users.read".into()],
                    input_digest: digest('3'),
                    compiled_digest: digest('4'),
                    compiled_at_unix_ms: 2_000,
                })
                .unwrap(),
            ),
            (
                WireContractFamily::AgentCapability,
                serde_json::to_value(AgentCapability {
                    agent_id: "agent-1".into(),
                    capability_id: "capability-1".into(),
                    tool_ids: vec!["graph.read".into()],
                    maximum_action_stage: AgentActionStage::Recommend,
                    evidence_source_refs: vec!["source:graph".into()],
                    definition_digest: digest('5'),
                })
                .unwrap(),
            ),
        ]
    }

    #[test]
    fn all_contract_families_round_trip_and_validate() {
        for (family, payload) in sample_payloads() {
            let original = envelope(family, payload);
            original.validate().unwrap();
            let encoded = serde_json::to_vec(&original).unwrap();
            let decoded: ExternalEventEnvelope = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(decoded, original);
            decoded.validate().unwrap();
        }
    }

    #[test]
    fn family_schema_and_payload_must_match() {
        let (_, payload) = sample_payloads().remove(0);
        let mut event = envelope(WireContractFamily::AgentActivity, payload);
        event.payload_schema_ref = THREAT_INTELLIGENCE_SCHEMA_V1.into();
        assert!(event.validate().is_err());

        event.payload_schema_ref = AGENT_ACTIVITY_SCHEMA_V1.into();
        event.contract_family = WireContractFamily::MetricSnapshot;
        assert!(event.validate().is_err());
    }

    #[test]
    fn omitted_evidence_fails_closed() {
        let state = WireEvidenceState::default();
        assert!(!state.supports_authoritative_decision());
        assert_eq!(state.completeness, EvidenceCompleteness::Partial);
        assert_eq!(state.freshness, EvidenceFreshness::Unknown);
    }

    #[test]
    fn signing_material_is_stable_and_excludes_signature_value() {
        let (family, payload) = sample_payloads().remove(0);
        let mut event = envelope(family, payload);
        let before = event.signing_bytes("ed25519", "key-1").unwrap();
        event.signature = Some(WireSignature {
            algorithm: "ed25519".into(),
            key_id: "key-1".into(),
            value: "signature-a".into(),
        });
        let after = event.signing_bytes("ed25519", "key-1").unwrap();
        assert_eq!(before, after);
        assert_ne!(event.digest().unwrap(), ContentDigest::of_bytes(before));
    }

    #[test]
    fn threat_promotion_requires_fresh_complete_evidence_and_a_gate_reason() {
        let observation = ThreatIntelligenceObservation {
            indicator_id: "indicator-1".into(),
            indicator_kind: ThreatIndicatorKind::IpAddress,
            normalized_value: "192.0.2.1".into(),
            verdict: ThreatVerdict::Malicious,
            score_basis_points: 9_000,
            confidence_basis_points: 8_000,
            source_count: 2,
            internal_observation_count: 0,
            first_seen_unix_ms: 1_000,
            last_seen_unix_ms: 2_000,
            valid_until_unix_ms: 4_000,
            source_event_refs: vec!["event:1".into(), "event:2".into()],
            evidence_refs: vec!["evidence:1".into()],
            promotion_reason: ThreatPromotionReason::MultiSourceCorroboration,
        };
        assert!(observation.supports_promotion(evidence(), 3_000));
        assert!(!observation.supports_promotion(WireEvidenceState::default(), 3_000));
        assert!(!observation.supports_promotion(evidence(), 4_000));
    }

    #[test]
    fn metric_verification_rejects_truncated_or_incomplete_evidence() {
        let metric = MetricSnapshot {
            metric_id: "metric-1".into(),
            definition_version: 1,
            observed_at_unix_ms: 2_000,
            value_microunits: 1,
            unit: "count".into(),
            truncated: false,
            evidence_refs: vec!["evidence:1".into()],
            snapshot_digest: digest('6'),
        };
        assert!(metric.is_verified(evidence()));
        assert!(!metric.is_verified(WireEvidenceState::default()));

        let mut truncated = metric;
        truncated.truncated = true;
        assert!(!truncated.is_verified(evidence()));
    }

    #[test]
    fn endpoint_lease_is_bounded_and_revocation_epoch_bound() {
        let lease = EndpointSessionLease {
            lease_id: "lease-1".into(),
            agent_id: "agent-1".into(),
            user_subject: "user:1".into(),
            session_id: "session-1".into(),
            operation: "repository.read".into(),
            repository_ref: "repository:example".into(),
            repository_revision: None,
            endpoint_ownership: EndpointOwnership::OrganizationOwned,
            network_profile: EndpointNetworkProfile::Isolated,
            capabilities: vec!["repository.read".into()],
            policy_id: "policy-1".into(),
            policy_revision: "revision-1".into(),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
            revocation_epoch: 4,
            audience: vec!["repository-broker".into()],
            posture_source_refs: vec!["source:endpoint".into()],
        };
        assert!(lease.is_active_at(1_500, 4));
        assert!(!lease.is_active_at(1_500, 5));
        assert!(!lease.is_active_at(2_000, 4));
    }

    #[test]
    fn receipt_states_are_consistent() {
        let receipt = WireIngestReceipt {
            event_id: "event-1".into(),
            event_digest: Some(digest('7')),
            outcome: WireIngestOutcome::Accepted,
            reason: WireIngestReason::Accepted,
            received_at_unix_ms: 2_000,
        };
        receipt.validate().unwrap();

        let mut invalid = receipt;
        invalid.event_digest = None;
        assert!(invalid.validate().is_err());
    }
}
