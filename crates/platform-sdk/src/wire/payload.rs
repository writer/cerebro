//! Strict typed payload families admitted by the common external-event envelope.
//!
//! Each family rejects unknown fields and validates bounded portable shape. The
//! payloads carry producer claims; validation does not authenticate producer or
//! tenant, recompute content digests, dereference evidence, authorize actions,
//! or persist graph state.

use serde::{Deserialize, Serialize};

use crate::{ActionState, SdkError};

use super::validation::{validate_digest, validate_id, validate_refs, validate_text};
use super::{EvidenceCompleteness, MAX_SESSION_LEASE_MS, WireEvidenceState};

/// Agent activity bound to policy, resource, and exact input/output content.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActivity {
    /// Stable identity of the agent session.
    pub session_id: String,
    /// Stable identity of the agent performing the activity.
    pub agent_id: String,
    /// Optional endpoint identity associated with the session.
    pub device_id: Option<String>,
    /// Machine-readable action performed or attempted.
    pub action: String,
    /// Stable reference to the affected resource.
    pub resource_ref: String,
    /// Exact policy revision used for the activity.
    pub policy_revision: String,
    /// Digest of the exact activity input.
    pub input_digest: String,
    /// Digest of the output or outcome, when one was produced.
    pub outcome_digest: Option<String>,
}

impl AgentActivity {
    /// Validates bounded identities and digest encoding.
    ///
    /// The optional outcome is not required for any particular action; producer
    /// lifecycle and policy enforcement own that stronger semantic relationship.
    ///
    /// # Errors
    ///
    /// Returns the first identifier or digest validation error.
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

/// Content-addressed endpoint observation with declared collection quality.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointTelemetry {
    /// Stable identity of the observed endpoint.
    pub endpoint_id: String,
    /// Agent that collected the observation.
    pub agent_id: String,
    /// Machine-readable observation family.
    pub observation_kind: String,
    /// Collector implementation or method identifier.
    pub collector: String,
    /// Machine-readable data-handling classification.
    pub privacy_class: String,
    /// Whether collection stopped before its declared population was exhausted.
    pub truncated: bool,
    /// Digest of the exact telemetry content stored elsewhere.
    pub content_digest: String,
    /// Bounded evidence references supporting the observation.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

impl EndpointTelemetry {
    /// Validates identities, digest and references, plus completeness consistency.
    ///
    /// A payload marked truncated cannot simultaneously claim complete envelope
    /// evidence. Empty or duplicate evidence references are structurally allowed,
    /// and the digest is syntax-checked rather than recomputed.
    ///
    /// # Errors
    ///
    /// Returns identifier, digest, or reference errors, or [`SdkError::Conflict`]
    /// for a truncated/complete contradiction.
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

/// Declared ownership class of an endpoint.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointOwnership {
    /// Endpoint is controlled by the organization.
    OrganizationOwned,
    /// Endpoint is personally owned and admitted under bring-your-own-device policy.
    BringYourOwnDevice,
    /// Producer cannot establish the ownership class.
    Unknown,
}

/// Declared network isolation profile for an endpoint session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointNetworkProfile {
    /// No network access is expected.
    Isolated,
    /// Access is limited to the declared external provider surface.
    ProviderOnly,
    /// Access is limited to build-related services.
    BuildOnly,
    /// Exceptional policy-authorized access profile.
    BreakGlass,
}

/// Time- and epoch-bounded endpoint session authorization claim.
///
/// The payload names the operation, repository scope, capabilities, audience,
/// policy revision, endpoint posture sources, and requested network profile. It
/// is not active authority until a trusted host verifies the envelope and policy,
/// compares revocation state, and applies the declared restrictions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointSessionLease {
    /// Stable identity of the lease.
    pub lease_id: String,
    /// Agent authorized by the lease.
    pub agent_id: String,
    /// Human or service subject on whose behalf the session runs.
    pub user_subject: String,
    /// Stable session identity.
    pub session_id: String,
    /// Machine-readable operation allowed by the lease.
    pub operation: String,
    /// Repository within the lease scope.
    pub repository_ref: String,
    /// Optional exact repository revision within scope.
    pub repository_revision: Option<String>,
    /// Declared ownership class used by policy.
    pub endpoint_ownership: EndpointOwnership,
    /// Declared network restriction profile.
    pub network_profile: EndpointNetworkProfile,
    /// Non-empty bounded capability identifiers.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Policy identity authorizing the lease.
    pub policy_id: String,
    /// Exact policy revision authorizing the lease.
    pub policy_revision: String,
    /// Non-zero inclusive Unix-millisecond lease start.
    pub issued_at_unix_ms: u64,
    /// Exclusive Unix-millisecond expiry, at most one hour after issue.
    pub expires_at_unix_ms: u64,
    /// Revocation epoch that must equal trusted current state.
    pub revocation_epoch: u64,
    /// Non-empty bounded audience identifiers.
    #[serde(default)]
    pub audience: Vec<String>,
    /// Bounded evidence references supporting endpoint posture.
    #[serde(default)]
    pub posture_source_refs: Vec<String>,
}

impl EndpointSessionLease {
    /// Validates identifier shape, lease duration, and bounded reference lists.
    ///
    /// Capability and audience lists must be non-empty. Reference validation
    /// allows duplicates, and posture evidence may be empty. This method does not
    /// resolve policy, authenticate the subject, or compare the revocation epoch.
    ///
    /// # Errors
    ///
    /// Returns identifier/reference errors, [`SdkError::OutOfRange`] for a zero,
    /// non-increasing, or longer-than-one-hour interval, or [`SdkError::Empty`]
    /// when capabilities or audience are missing.
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
    ///
    /// The start is inclusive and expiration exclusive. This pure predicate
    /// trusts both supplied values and does not authenticate the envelope,
    /// authorize the operation, or consult durable revocation state itself.
    pub fn is_active_at(&self, now_unix_ms: u64, current_revocation_epoch: u64) -> bool {
        self.validate().is_ok()
            && now_unix_ms >= self.issued_at_unix_ms
            && now_unix_ms < self.expires_at_unix_ms
            && self.revocation_epoch == current_revocation_epoch
    }
}

/// Normalized threat-indicator value family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatIndicatorKind {
    /// DNS domain name.
    Domain,
    /// IPv4 or IPv6 address.
    IpAddress,
    /// Uniform resource locator.
    Url,
    /// Content or executable file hash.
    FileHash,
    /// Email address.
    EmailAddress,
}

/// Producer assessment of one threat indicator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatVerdict {
    /// No verdict could be established.
    Unknown,
    /// Indicator is assessed as benign.
    Benign,
    /// Indicator warrants investigation but is not confirmed malicious.
    Suspicious,
    /// Indicator is assessed as malicious.
    Malicious,
}

/// Evidence path claimed for canonical graph promotion.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatPromotionReason {
    /// At least one internal observation supports promotion.
    InternalObservation,
    /// Multiple source observations support promotion.
    MultiSourceCorroboration,
    /// Producer does not request promotion.
    NotPromoted,
}

/// Bounded threat-intelligence observation and promotion claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatIntelligenceObservation {
    /// Stable identity of the normalized indicator.
    pub indicator_id: String,
    /// Interpretation of [`Self::normalized_value`].
    pub indicator_kind: ThreatIndicatorKind,
    /// Producer-normalized indicator text.
    pub normalized_value: String,
    /// Producer verdict.
    pub verdict: ThreatVerdict,
    /// Score in the inclusive basis-point range `0..=10_000`.
    pub score_basis_points: u16,
    /// Confidence in the inclusive basis-point range `0..=10_000`.
    pub confidence_basis_points: u16,
    /// Non-zero number of contributing sources claimed by the producer.
    pub source_count: u16,
    /// Contributing observations from internal sources, no greater than source count.
    pub internal_observation_count: u64,
    /// Non-zero Unix-millisecond first observation time.
    pub first_seen_unix_ms: u64,
    /// Unix-millisecond latest observation time, no earlier than first seen.
    pub last_seen_unix_ms: u64,
    /// Exclusive Unix-millisecond validity deadline after last seen.
    pub valid_until_unix_ms: u64,
    /// Bounded source-event references used for corroboration.
    #[serde(default)]
    pub source_event_refs: Vec<String>,
    /// Bounded evidence references supporting the verdict.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Producer-claimed route into canonical graph consideration.
    pub promotion_reason: ThreatPromotionReason,
}

impl ThreatIntelligenceObservation {
    /// Validates identifiers, score/count ranges, time ordering, and references.
    ///
    /// Reference lists may be empty or contain duplicates. This check does not
    /// normalize the indicator according to its kind or reconcile numeric source
    /// counts with distinct referenced source identities.
    ///
    /// # Errors
    ///
    /// Returns identifier/text/reference errors or [`SdkError::OutOfRange`] for
    /// scores above 10,000, invalid source counts, or invalid observation times.
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
    ///
    /// Promotion requires valid shape, complete and fresh envelope evidence, a
    /// malicious verdict, a deadline strictly after `now_unix_ms`, and non-empty
    /// source and evidence references. Internal promotion requires a positive
    /// internal count. Multi-source promotion requires a declared source count of
    /// at least two and at least two source-event entries.
    ///
    /// Reference uniqueness is not checked, and `now_unix_ms` is compared only
    /// with expiration, not first/last observation time. The admission host must
    /// verify authenticated source diversity, trusted time, and tenant policy.
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

/// Producer-reported lifecycle outcome for one remediation operation.
///
/// The payload binds stable action identifiers to proposal and optional provider
/// or verification receipt digests. Shape validation does not enforce which
/// receipts must be present for a given [`ActionState`] or verify the referenced
/// durable action operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationOutcome {
    /// Stable action operation identity.
    pub operation_id: String,
    /// Finding that motivated the remediation.
    pub finding_id: String,
    /// Machine-readable action kind.
    pub action_kind: String,
    /// Primary remediated target identity.
    pub target_id: String,
    /// Producer-reported durable action state.
    pub state: ActionState,
    /// Idempotency key associated with the action.
    pub idempotency_key: String,
    /// Digest of the exact action proposal.
    pub proposal_digest: String,
    /// Optional digest of provider execution evidence.
    pub provider_receipt_digest: Option<String>,
    /// Optional digest of independent verification evidence.
    pub verification_receipt_digest: Option<String>,
}

impl RemediationOutcome {
    /// Validates identifier and digest encoding only.
    ///
    /// # Errors
    ///
    /// Returns the first identifier or digest validation error.
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

/// Fixed-point metric observation with bounded evidence references.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricSnapshot {
    /// Stable metric definition identity.
    pub metric_id: String,
    /// Non-zero metric definition version.
    pub definition_version: u64,
    /// Non-zero Unix-millisecond observation time.
    pub observed_at_unix_ms: u64,
    /// Signed value in millionths of [`Self::unit`].
    pub value_microunits: i64,
    /// Machine-readable unit identifier.
    pub unit: String,
    /// Whether aggregation stopped before the declared population was exhausted.
    pub truncated: bool,
    /// Bounded evidence references supporting the value.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Digest of the exact metric snapshot material.
    pub snapshot_digest: String,
}

impl MetricSnapshot {
    /// Validates identity, digest, references, version/time, and evidence consistency.
    ///
    /// Any signed microunit value is structurally valid. Empty or duplicate
    /// evidence references are allowed, and the snapshot digest is not recomputed.
    /// A truncated payload cannot claim complete envelope evidence.
    ///
    /// # Errors
    ///
    /// Returns identifier/digest/reference errors, [`SdkError::OutOfRange`] for
    /// zero version or time, or [`SdkError::Conflict`] for truncated/complete
    /// evidence contradiction.
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
    ///
    /// Verification requires valid shape, complete and fresh evidence, a
    /// non-truncated payload, and at least one evidence reference. It does not
    /// authenticate evidence or recompute [`Self::snapshot_digest`].
    pub fn is_verified(&self, evidence: WireEvidenceState) -> bool {
        self.validate(evidence).is_ok()
            && evidence.supports_authoritative_decision()
            && !self.truncated
            && !self.evidence_refs.is_empty()
    }
}

/// Producer-reported scanner severity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerSeverity {
    /// Highest-impact scanner classification.
    Critical,
    /// High-impact scanner classification.
    High,
    /// Medium-impact scanner classification.
    Medium,
    /// Low-impact scanner classification.
    Low,
    /// Informational observation without declared impact.
    Informational,
    /// Producer could not map severity into the closed vocabulary.
    Unknown,
}

/// Producer-reported validation state for a scanner finding.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerValidationState {
    /// Producer reports that the finding passed its validation process.
    Validated,
    /// Finding requires an independent review decision.
    NeedsReview,
    /// Finding is intentionally suppressed by producer policy.
    Suppressed,
    /// Producer validation rejected the finding.
    Rejected,
}

/// Content-addressed finding emitted by an external scanner.
///
/// Severity and validation state are producer claims. Admission validates shape
/// but does not treat `Validated` as platform authority, apply suppression policy,
/// or require optional location, evidence, and fixed-version text for any state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerFinding {
    /// Stable producer finding identity.
    pub finding_id: String,
    /// Stable scanner identity.
    pub scanner_id: String,
    /// Stable scanner rule identity.
    pub rule_id: String,
    /// Exact scanner rule version.
    pub rule_version: String,
    /// Producer severity classification.
    pub severity: ScannerSeverity,
    /// Producer validation classification.
    pub validation_state: ScannerValidationState,
    /// Stable reference to the scanned subject.
    pub subject_ref: String,
    /// Exact source revision scanned.
    pub source_revision: String,
    /// Optional bounded human-readable source location.
    pub location_ref: Option<String>,
    /// Digest of the exact finding evidence.
    pub evidence_digest: String,
    /// Optional bounded reference or locator for the evidence.
    pub evidence_ref: Option<String>,
    /// Optional bounded version in which the issue is fixed.
    pub fixed_version: Option<String>,
}

impl ScannerFinding {
    /// Validates required identifiers, evidence digest, and optional text bounds.
    ///
    /// # Errors
    ///
    /// Returns the first identifier, digest, or text validation error.
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

/// Content-addressed declarative connector compilation result.
///
/// `auth_kind` names a credential mechanism but must never contain credential
/// bytes or an environment-specific secret address. The manifest declares
/// object and capability families; it does not resolve credentials, construct
/// requests, or prove that the compiled digest was produced from the input digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorManifest {
    /// Stable connector identity.
    pub connector_id: String,
    /// Non-zero manifest version.
    pub manifest_version: u64,
    /// Non-secret authentication mechanism identifier.
    pub auth_kind: String,
    /// Non-empty bounded provider object-family identifiers.
    #[serde(default)]
    pub object_kinds: Vec<String>,
    /// Bounded connector capability identifiers.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Digest of canonical declarative input.
    pub input_digest: String,
    /// Digest of compiled connector material.
    pub compiled_digest: String,
    /// Non-zero Unix-millisecond compilation time.
    pub compiled_at_unix_ms: u64,
}

impl ConnectorManifest {
    /// Validates identifiers, bounded references, digests, version, and time.
    ///
    /// Object kinds must be non-empty; capabilities may be empty. Both vectors
    /// may contain duplicates. Digest relationship and compiler provenance are
    /// intentionally left to the trusted connector compiler.
    ///
    /// # Errors
    ///
    /// Returns identifier/reference/digest errors or [`SdkError::OutOfRange`]
    /// for zero version, zero compilation time, or no object kinds.
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

/// Content-addressed advertisement of one agent capability.
///
/// This is discovery metadata rather than a grant. An advertised `Execute`
/// stage does not authorize any action; policy, mandate, tenant, target, and
/// human/service authority checks remain operation-specific.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCapability {
    /// Stable identity of the advertising agent.
    pub agent_id: String,
    /// Stable identity of the advertised capability.
    pub capability_id: String,
    /// Non-empty bounded tool identifiers available to the capability.
    #[serde(default)]
    pub tool_ids: Vec<String>,
    /// Highest action-lifecycle stage the capability can request.
    pub maximum_action_stage: AgentActionStage,
    /// Non-empty bounded references to evidence sources the capability can use.
    #[serde(default)]
    pub evidence_source_refs: Vec<String>,
    /// Digest of the exact capability definition.
    pub definition_digest: String,
}

impl AgentCapability {
    /// Validates identity, required references, and definition-digest syntax.
    ///
    /// Tool and evidence-source vectors contain at most 512 entries each, must
    /// be non-empty, and may contain duplicates. The digest is not recomputed.
    ///
    /// # Errors
    ///
    /// Returns identifier/reference/digest errors or [`SdkError::Empty`] when
    /// tools or evidence sources are absent.
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
    /// Read and report state without recommending a change.
    Observe,
    /// Recommend a possible change without constructing an action proposal.
    Recommend,
    /// Construct a proposal that still requires independent authorization.
    Propose,
    /// Request execution after all independent action gates have passed.
    Execute,
}
