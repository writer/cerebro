use serde::{Deserialize, Serialize};

use crate::{ActionState, SdkError};

use super::validation::{validate_digest, validate_id, validate_refs, validate_text};
use super::{EvidenceCompleteness, MAX_SESSION_LEASE_MS, WireEvidenceState};

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
    pub(super) fn validate(&self) -> Result<(), SdkError> {
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
    pub(super) fn validate(&self, evidence: WireEvidenceState) -> Result<(), SdkError> {
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
    pub(super) fn validate(&self) -> Result<(), SdkError> {
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
    pub(super) fn validate(&self) -> Result<(), SdkError> {
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
    pub(super) fn validate(&self) -> Result<(), SdkError> {
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
    pub(super) fn validate(&self, evidence: WireEvidenceState) -> Result<(), SdkError> {
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
    pub(super) fn validate(&self) -> Result<(), SdkError> {
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
    pub(super) fn validate(&self) -> Result<(), SdkError> {
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
    pub(super) fn validate(&self) -> Result<(), SdkError> {
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
