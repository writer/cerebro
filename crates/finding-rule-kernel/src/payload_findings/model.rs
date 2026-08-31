//! Shared admission model for payload-backed finding rules.
//!
//! This module binds trusted runtime context to one replayed event, preflights
//! arbitrary JSON under strict structural budgets, normalizes host authority
//! time, and supplies deterministic identity helpers. Provider payload fields
//! never choose tenant, workspace, runtime, source, or observation time.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::digest::sha256;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Maximum raw JSON bytes accepted by a payload-backed rule.
pub(crate) const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
/// Maximum nested JSON value depth, counting the top-level value as one.
pub(crate) const MAX_PAYLOAD_DEPTH: usize = 8;
/// Maximum elements admitted by any one JSON array.
pub(crate) const MAX_PAYLOAD_ARRAY_ITEMS: usize = 64;
/// Maximum unique fields admitted by any one JSON object.
pub(crate) const MAX_PAYLOAD_OBJECT_FIELDS: usize = 64;
/// Maximum UTF-8 bytes in a JSON string value or object key.
pub(crate) const MAX_PAYLOAD_STRING_BYTES: usize = 8 * 1024;
/// Maximum trusted overlay attributes admitted with one event.
const MAX_ATTRIBUTES: usize = 64;
/// Maximum UTF-8 bytes in one trusted attribute key.
const MAX_ATTRIBUTE_KEY_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed operation requested from a payload rule.
pub(crate) enum Operation {
    /// Evaluate an event for a new or recurring finding.
    Evaluate,
    /// Derive the stable anchor of an open finding.
    OpenAnchor,
    /// Evaluate an event as possible remediation evidence.
    Close,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Lifecycle action emitted by a payload rule.
pub(crate) enum Action {
    /// Event does not change finding state.
    None,
    /// Open or recur the returned finding.
    Open,
    /// Close the finding selected by the returned anchor.
    Close,
    /// Return the stable anchor without a finding body.
    OpenAnchor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Host-authenticated runtime scope that provider JSON cannot override.
pub(crate) struct TrustedRuntime {
    /// Concrete collector or runtime identity.
    pub(crate) runtime_id: String,
    /// Closed provider source family.
    pub(crate) source_id: String,
    /// Authenticated tenant identity.
    pub(crate) tenant_id: String,
    /// Trusted application workspace used by storage isolation.
    pub(crate) workspace_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One bounded replayed event plus its trusted host overlay.
pub(crate) struct EventInput {
    /// Stable event identity.
    pub(crate) id: String,
    /// Tenant copied from authenticated admission context.
    pub(crate) tenant_id: String,
    /// Source family admitted by the host.
    pub(crate) source_id: String,
    /// Closed event kind selected for rule matching.
    pub(crate) kind: String,
    /// Exact event schema admitted before kernel execution.
    pub(crate) schema_ref: String,
    /// Host-supplied observation time. Provider payload time fields are closed.
    pub(crate) observed_at: String,
    /// Host-supplied deterministic replay order for equal timestamps.
    pub(crate) replay_sequence: u64,
    /// Bounded non-payload metadata supplied by the trusted host.
    pub(crate) attributes: BTreeMap<String, String>,
    /// Original provider JSON bytes evaluated under structural budgets.
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Complete credential-free input to one payload-backed rule.
pub(crate) struct RuleRequest {
    /// Requested lifecycle operation.
    pub(crate) operation: Operation,
    /// Exact compiled rule identifier.
    pub(crate) rule_id: String,
    /// Authenticated runtime scope.
    pub(crate) runtime: TrustedRuntime,
    /// Replayed event and bounded payload.
    pub(crate) event: EventInput,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Framework-native control reference attached to a rule finding.
pub(crate) struct ControlRef {
    /// Display name of the framework.
    pub(crate) framework_name: String,
    /// Framework-native control identifier.
    pub(crate) control_id: String,
}

/// Closed rule-decision subset staged for conversion by the shared host seam.
///
/// This is not the complete mutable `ports.FindingRecord`: graph evidence,
/// risk, workflow, and tombstone state remain host-owned and must be compared
/// after the shared DTO conversion supplies their exact zero/default values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct RuleFindingDecision {
    #[serde(rename = "ID")]
    pub(crate) id: String,
    #[serde(rename = "Fingerprint")]
    pub(crate) fingerprint: String,
    #[serde(rename = "TenantID")]
    pub(crate) tenant_id: String,
    #[serde(rename = "RuntimeID")]
    pub(crate) runtime_id: String,
    #[serde(rename = "RuleID")]
    pub(crate) rule_id: String,
    #[serde(rename = "Title")]
    pub(crate) title: String,
    #[serde(rename = "Severity")]
    pub(crate) severity: String,
    #[serde(rename = "Status")]
    pub(crate) status: String,
    #[serde(rename = "Summary")]
    pub(crate) summary: String,
    #[serde(rename = "ResourceURNs")]
    pub(crate) resource_urns: Vec<String>,
    #[serde(rename = "EventIDs")]
    pub(crate) event_ids: Vec<String>,
    #[serde(rename = "ObservedPolicyIDs")]
    pub(crate) observed_policy_ids: Option<Vec<String>>,
    #[serde(rename = "PolicyID")]
    pub(crate) policy_id: String,
    #[serde(rename = "PolicyName")]
    pub(crate) policy_name: String,
    #[serde(rename = "CheckID")]
    pub(crate) check_id: String,
    #[serde(rename = "CheckName")]
    pub(crate) check_name: String,
    #[serde(rename = "ControlRefs")]
    pub(crate) control_refs: Vec<ControlRef>,
    #[serde(rename = "Attributes")]
    pub(crate) attributes: BTreeMap<String, String>,
    #[serde(rename = "FirstObservedAt")]
    pub(crate) first_observed_at: String,
    #[serde(rename = "LastObservedAt")]
    pub(crate) last_observed_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Structurally valid lifecycle decision produced by one rule evaluator.
pub(crate) struct Decision {
    /// Requested host lifecycle transition.
    pub(crate) action: Action,
    /// Stable open-finding selector for anchor and close responses.
    pub(crate) anchor: String,
    /// Rule-owned finding subset for an open response.
    pub(crate) finding: Option<RuleFindingDecision>,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
/// Test oracle binding an injected evaluator to exact input and output digests.
pub(crate) struct EvaluatorReceipt {
    pub(crate) workspace_id: String,
    pub(crate) tenant_id: String,
    pub(crate) runtime_id: String,
    pub(crate) source_id: String,
    pub(crate) rule_id: String,
    pub(crate) definition_digest: String,
    pub(crate) input_digest: String,
    pub(crate) output_digest: String,
    pub(crate) action: Action,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
/// Test-only pairing of an injected evaluator result and its receipt.
pub(crate) struct EvaluatorOutput {
    pub(crate) decision: Decision,
    pub(crate) receipt: EvaluatorReceipt,
}

/// Trusted host scope carried alongside a raw rule decision.
///
/// Workspace is deliberately absent from the public finding identity and raw
/// rule record. The shared adapter must retain this envelope through candidate
/// evaluation, upsert, and closeout so storage can enforce workspace scope.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScopedDecision {
    pub(crate) workspace_id: String,
    pub(crate) tenant_id: String,
    pub(crate) runtime_id: String,
    pub(crate) source_id: String,
    pub(crate) rule_id: String,
    pub(crate) event_id: String,
    pub(crate) observed_at: String,
    pub(crate) replay_sequence: u64,
    pub(crate) decision: Decision,
}

#[cfg(test)]
impl ScopedDecision {
    /// Returns the decision only when the caller presents the retained workspace.
    pub(crate) fn require_workspace(&self, workspace_id: &str) -> Result<&Decision, KernelError> {
        if workspace_id.trim().is_empty() || self.workspace_id != workspace_id.trim() {
            return Err(KernelError::WorkspaceMismatch);
        }
        Ok(&self.decision)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Persistence seam exercised by workspace-retention parity tests.
pub(crate) enum PersistencePath {
    /// Candidate evaluation before persistence.
    Candidate,
    /// Production finding upsert.
    ProductionUpsert,
    /// Finding closeout.
    Closeout,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
/// Test-only persistence action that must retain all trusted scope coordinates.
pub(crate) struct ScopedPersistenceAction {
    pub(crate) workspace_id: String,
    pub(crate) tenant_id: String,
    pub(crate) runtime_id: String,
    pub(crate) source_id: String,
    pub(crate) rule_id: String,
    pub(crate) event_id: String,
    pub(crate) observed_at: String,
    pub(crate) replay_sequence: u64,
    pub(crate) path: PersistencePath,
    pub(crate) decision: Decision,
}

#[cfg(test)]
impl ScopedDecision {
    /// Copies one scoped decision into a selected persistence path.
    pub(crate) fn for_path(&self, path: PersistencePath) -> ScopedPersistenceAction {
        ScopedPersistenceAction {
            workspace_id: self.workspace_id.clone(),
            tenant_id: self.tenant_id.clone(),
            runtime_id: self.runtime_id.clone(),
            source_id: self.source_id.clone(),
            rule_id: self.rule_id.clone(),
            event_id: self.event_id.clone(),
            observed_at: self.observed_at.clone(),
            replay_sequence: self.replay_sequence,
            path,
            decision: self.decision.clone(),
        }
    }
}

/// Exact zero/default host-owned fields embedded by Go's `FindingRecord`.
/// `Option<Vec<_>>` preserves nil versus explicitly empty slices.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct HostFindingFields {
    #[serde(rename = "GraphEvidenceRows")]
    pub(crate) graph_evidence_rows: Option<Vec<serde_json::Value>>,
    #[serde(rename = "RiskScore")]
    pub(crate) risk_score: i32,
    #[serde(rename = "LikelihoodScore")]
    pub(crate) likelihood_score: i32,
    #[serde(rename = "ImpactScore")]
    pub(crate) impact_score: i32,
    #[serde(rename = "ConfidenceScore")]
    pub(crate) confidence_score: i32,
    #[serde(rename = "LikelihoodLevel")]
    pub(crate) likelihood_level: String,
    #[serde(rename = "ImpactLevel")]
    pub(crate) impact_level: String,
    #[serde(rename = "RiskReasons")]
    pub(crate) risk_reasons: Option<Vec<String>>,
    #[serde(rename = "RiskFactors")]
    pub(crate) risk_factors: Option<Vec<serde_json::Value>>,
    #[serde(rename = "RiskModelVersion")]
    pub(crate) risk_model_version: String,
    #[serde(rename = "Notes")]
    pub(crate) notes: Option<Vec<serde_json::Value>>,
    #[serde(rename = "Tickets")]
    pub(crate) tickets: Option<Vec<serde_json::Value>>,
    #[serde(rename = "ExternalRefs")]
    pub(crate) external_refs: Option<Vec<serde_json::Value>>,
    #[serde(rename = "Assignee")]
    pub(crate) assignee: String,
    #[serde(rename = "DueAt")]
    pub(crate) due_at: String,
    #[serde(rename = "StatusReason")]
    pub(crate) status_reason: String,
    #[serde(rename = "StatusUpdatedAt")]
    pub(crate) status_updated_at: String,
    #[serde(rename = "Tombstoned")]
    pub(crate) tombstoned: bool,
    #[serde(rename = "TombstonedAt")]
    pub(crate) tombstoned_at: String,
    #[serde(rename = "TombstonedBy")]
    pub(crate) tombstoned_by: String,
    #[serde(rename = "TombstonedReason")]
    pub(crate) tombstoned_reason: String,
    #[serde(rename = "TombstonedRunID")]
    pub(crate) tombstoned_run_id: String,
    #[serde(rename = "PriorStatus")]
    pub(crate) prior_status: String,
    #[serde(rename = "TombstoneGeneration")]
    pub(crate) tombstone_generation: i32,
}

#[cfg(test)]
impl Default for HostFindingFields {
    /// Reproduces Go zero values used by the shared finding conversion seam.
    fn default() -> Self {
        const GO_ZERO_TIME: &str = "0001-01-01T00:00:00Z";
        Self {
            graph_evidence_rows: None,
            risk_score: 0,
            likelihood_score: 0,
            impact_score: 0,
            confidence_score: 0,
            likelihood_level: String::new(),
            impact_level: String::new(),
            risk_reasons: None,
            risk_factors: None,
            risk_model_version: String::new(),
            notes: None,
            tickets: None,
            external_refs: None,
            assignee: String::new(),
            due_at: GO_ZERO_TIME.into(),
            status_reason: String::new(),
            status_updated_at: GO_ZERO_TIME.into(),
            tombstoned: false,
            tombstoned_at: GO_ZERO_TIME.into(),
            tombstoned_by: String::new(),
            tombstoned_reason: String::new(),
            tombstoned_run_id: String::new(),
            prior_status: String::new(),
            tombstone_generation: 0,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Full parity record combining rule-owned and host-owned finding fields.
pub(crate) struct CompleteFindingRecord {
    #[serde(flatten)]
    pub(crate) rule: RuleFindingDecision,
    #[serde(flatten)]
    pub(crate) host: HostFindingFields,
}

#[cfg(test)]
impl From<RuleFindingDecision> for CompleteFindingRecord {
    /// Adds the exact host-owned zero/default field set to a rule decision.
    fn from(rule: RuleFindingDecision) -> Self {
        Self {
            rule,
            host: HostFindingFields::default(),
        }
    }
}

#[cfg(test)]
impl CompleteFindingRecord {
    /// Applies a fresh rule decision without erasing analyst-managed state.
    pub(crate) fn overlay_preserving_host_state(&self, mut rule: RuleFindingDecision) -> Self {
        if matches!(self.rule.status.as_str(), "suppressed" | "resolved") {
            rule.status.clone_from(&self.rule.status);
        }
        Self {
            rule,
            host: self.host.clone(),
        }
    }
}

impl Decision {
    /// Constructs a structurally empty non-match decision.
    pub(super) fn none() -> Self {
        Self {
            action: Action::None,
            anchor: String::new(),
            finding: None,
        }
    }

    /// Constructs an anchor response, degrading an empty anchor to `None`.
    pub(super) fn anchor(anchor: String) -> Self {
        if anchor.trim().is_empty() {
            return Self::none();
        }
        Self {
            action: Action::OpenAnchor,
            anchor,
            finding: None,
        }
    }

    /// Constructs an open action with exactly one finding body.
    pub(super) fn open(finding: RuleFindingDecision) -> Self {
        Self {
            action: Action::Open,
            anchor: String::new(),
            finding: Some(finding),
        }
    }

    /// Constructs a close action with no finding body.
    pub(super) fn close(anchor: String) -> Self {
        Self {
            action: Action::Close,
            anchor,
            finding: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Typed failure at the payload-rule admission or evaluation boundary.
pub(crate) enum KernelError {
    /// Rule identifier is not compiled into this evaluator.
    UnsupportedRule,
    /// Rule does not implement the requested lifecycle operation.
    UnsupportedOperation,
    /// Runtime and event tenant, source, or runtime coordinates disagree.
    ScopeMismatch,
    /// Trusted event workspace disagrees with runtime workspace.
    WorkspaceMismatch,
    /// Event schema does not match the rule contract.
    SchemaMismatch,
    /// Anchor or close requests unexpectedly carried provider bytes.
    ActionPayloadNotEmpty,
    /// Required host-authenticated scope is absent.
    MissingTrustedContext,
    /// Injected evaluator failed before producing a decision.
    EvaluatorFailure,
    /// Evaluator decision shape or operation is invalid.
    MalformedEvaluatorResponse,
    /// Evaluator receipt or finding binding is inconsistent.
    InvalidEvaluatorReceipt,
    /// Raw payload exceeds [`MAX_PAYLOAD_BYTES`].
    PayloadTooLarge,
    /// JSON nesting exceeds [`MAX_PAYLOAD_DEPTH`].
    PayloadTooDeep,
    /// A JSON array exceeds [`MAX_PAYLOAD_ARRAY_ITEMS`].
    PayloadArrayTooLarge,
    /// A JSON object exceeds [`MAX_PAYLOAD_OBJECT_FIELDS`].
    PayloadObjectTooLarge,
    /// A JSON string or key exceeds [`MAX_PAYLOAD_STRING_BYTES`].
    PayloadStringTooLarge,
    /// A JSON object repeats a field name.
    DuplicatePayloadField,
    /// JSON is invalid, trailing, or outside the target rule schema.
    MalformedPayload,
    /// Host authority time is not supported RFC 3339 input.
    InvalidObservationTime,
    /// Trusted attribute map exceeds its count or field bounds.
    InvalidAttributes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Provider scalar normalized to the historical Go string representation.
pub(super) struct CanonicalScalar(String);

impl CanonicalScalar {
    /// Returns the already normalized scalar value.
    pub(super) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for CanonicalScalar {
    /// Accepts only string, Boolean, or number JSON scalars.
    ///
    /// Strings are trimmed, Booleans use lowercase Rust spelling, and numbers
    /// pass through the Go-compatible `f64` normalization below.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let normalized = match value {
            Value::String(value) => value.trim().to_owned(),
            Value::Bool(value) => value.to_string(),
            Value::Number(value) => canonical_number(&value.to_string())
                .ok_or_else(|| serde::de::Error::custom("number is not canonical"))?,
            _ => {
                return Err(serde::de::Error::custom(
                    "payload field must be a string, boolean, or number",
                ));
            }
        };
        Ok(Self(normalized))
    }
}

pub(super) fn validate_scope(
    request: &RuleRequest,
    source_id: &str,
    schema_ref: &str,
) -> Result<(), KernelError> {
    let runtime = &request.runtime;
    let event = &request.event;
    // Establish all required host coordinates before comparing them. Workspace
    // is mandatory for payload families because persistence is workspace-scoped.
    if runtime.runtime_id.trim().is_empty()
        || runtime.tenant_id.trim().is_empty()
        || runtime.source_id.trim().is_empty()
        || runtime.workspace_id.trim().is_empty()
        || event.id.trim().is_empty()
        || event.tenant_id.trim().is_empty()
    {
        return Err(KernelError::MissingTrustedContext);
    }
    // Source comparison is ASCII case-insensitive for compatibility; tenant and
    // runtime identities retain exact trimmed comparison.
    if runtime.tenant_id.trim() != event.tenant_id.trim()
        || !runtime.source_id.trim().eq_ignore_ascii_case(source_id)
        || !event.source_id.trim().eq_ignore_ascii_case(source_id)
    {
        return Err(KernelError::ScopeMismatch);
    }
    // Schema identity is exact because it selects the closed payload decoder.
    if event.schema_ref.trim() != schema_ref {
        return Err(KernelError::SchemaMismatch);
    }
    let event_runtime = attribute(event, "source_runtime_id");
    if !event_runtime.is_empty() && event_runtime != runtime.runtime_id.trim() {
        return Err(KernelError::ScopeMismatch);
    }
    // This attribute may only be supplied by the trusted host overlay. Payload
    // workspace fields are rejected by the closed schema. If the attribute is
    // present, it must agree with the independently trusted runtime context.
    let event_workspace = attribute(event, "cerebro_application_workspace_id");
    if !event_workspace.is_empty() && event_workspace != runtime.workspace_id.trim() {
        return Err(KernelError::WorkspaceMismatch);
    }
    validate_attributes(&event.attributes)
}

fn validate_attributes(attributes: &BTreeMap<String, String>) -> Result<(), KernelError> {
    // Attributes are already a trusted host overlay, but still need independent
    // cardinality and byte bounds before a rule copies them into findings.
    if attributes.len() > MAX_ATTRIBUTES {
        return Err(KernelError::InvalidAttributes);
    }
    if attributes.iter().any(|(key, value)| {
        key.trim().is_empty()
            || key.len() > MAX_ATTRIBUTE_KEY_BYTES
            || value.len() > MAX_PAYLOAD_STRING_BYTES
    }) {
        return Err(KernelError::InvalidAttributes);
    }
    Ok(())
}

pub(super) fn decode_payload<T>(payload: &[u8]) -> Result<T, KernelError>
where
    T: for<'de> Deserialize<'de> + Default,
{
    // An absent provider body maps only to the target's explicit `Default`, which
    // keeps optional payloads distinct from malformed non-empty JSON.
    if payload.is_empty() {
        return Ok(T::default());
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(KernelError::PayloadTooLarge);
    }
    // Preflight the generic JSON tree before target deserialization. This catches
    // duplicate fields and structural budgets that ordinary Serde derives do not.
    let failure = Cell::new(None);
    let mut preflight = serde_json::Deserializer::from_slice(payload);
    if (BoundedValueSeed {
        depth: 1,
        failure: &failure,
    })
    .deserialize(&mut preflight)
    .is_err()
    {
        return Err(match failure.get() {
            Some(BudgetFailure::Depth) => KernelError::PayloadTooDeep,
            Some(BudgetFailure::Array) => KernelError::PayloadArrayTooLarge,
            Some(BudgetFailure::Object) => KernelError::PayloadObjectTooLarge,
            Some(BudgetFailure::String) => KernelError::PayloadStringTooLarge,
            Some(BudgetFailure::Duplicate) => KernelError::DuplicatePayloadField,
            None => KernelError::MalformedPayload,
        });
    }
    preflight.end().map_err(|_| KernelError::MalformedPayload)?;
    // Decode a second time only after the entire generic value and trailing-byte
    // check pass; the closed target schema supplies semantic field validation.
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let decoded = T::deserialize(&mut deserializer).map_err(|_| KernelError::MalformedPayload)?;
    deserializer
        .end()
        .map_err(|_| KernelError::MalformedPayload)?;
    Ok(decoded)
}

#[derive(Clone, Copy)]
/// Exact budget first exceeded during generic JSON preflight.
enum BudgetFailure {
    Depth,
    Array,
    Object,
    String,
    Duplicate,
}

struct BoundedValueSeed<'a> {
    /// Current value depth, with the root at one.
    depth: usize,
    /// Shared first-failure class propagated out of Serde's generic error.
    failure: &'a Cell<Option<BudgetFailure>>,
}

impl<'a, 'de> DeserializeSeed<'de> for BoundedValueSeed<'a> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Check before descending so every scalar, sequence, and map at this
        // position participates in the same depth accounting.
        if self.depth > MAX_PAYLOAD_DEPTH {
            self.failure.set(Some(BudgetFailure::Depth));
            return Err(serde::de::Error::custom("payload budget exceeded"));
        }
        deserializer.deserialize_any(BoundedValueVisitor {
            depth: self.depth,
            failure: self.failure,
        })
    }
}

struct BoundedValueVisitor<'a> {
    /// Depth of the value currently being visited.
    depth: usize,
    /// Out-of-band typed failure retained across Serde callbacks.
    failure: &'a Cell<Option<BudgetFailure>>,
}

impl<'a, 'de> Visitor<'de> for BoundedValueVisitor<'a> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded JSON")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX_PAYLOAD_STRING_BYTES {
            self.failure.set(Some(BudgetFailure::String));
            return Err(E::custom("payload budget exceeded"));
        }
        Ok(())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        // Count elements as they are recursively consumed; reject immediately
        // after consuming the first item beyond the closed per-array budget.
        let mut count = 0;
        while sequence
            .next_element_seed(BoundedValueSeed {
                depth: self.depth + 1,
                failure: self.failure,
            })?
            .is_some()
        {
            count += 1;
            if count > MAX_PAYLOAD_ARRAY_ITEMS {
                self.failure.set(Some(BudgetFailure::Array));
                return Err(serde::de::Error::custom("payload budget exceeded"));
            }
        }
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        // Retaining keys for one bounded object enables exact duplicate rejection
        // before target deserialization could apply last-key-wins semantics.
        let mut keys = std::collections::BTreeSet::new();
        let mut count = 0;
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > MAX_PAYLOAD_STRING_BYTES {
                self.failure.set(Some(BudgetFailure::String));
                return Err(serde::de::Error::custom("payload budget exceeded"));
            }
            if !keys.insert(key.clone()) {
                self.failure.set(Some(BudgetFailure::Duplicate));
                return Err(serde::de::Error::custom("duplicate payload field"));
            }
            count += 1;
            if count > MAX_PAYLOAD_OBJECT_FIELDS {
                self.failure.set(Some(BudgetFailure::Object));
                return Err(serde::de::Error::custom("payload budget exceeded"));
            }
            map.next_value_seed(BoundedValueSeed {
                depth: self.depth + 1,
                failure: self.failure,
            })?;
        }
        Ok(())
    }
}

pub(crate) fn normalized_observation_time(value: &str) -> Result<String, KernelError> {
    // ASCII is required before fixed byte slicing. Accept UTC `Z` or a numeric
    // offset, then normalize every valid instant into a UTC representation.
    let value = value.trim();
    if !value.is_ascii() {
        return Err(KernelError::InvalidObservationTime);
    }
    let (date_time, offset_seconds) = if let Some(value) = value.strip_suffix('Z') {
        (value, 0_i64)
    } else {
        let offset_index = value
            .char_indices()
            .rev()
            .find(|(index, character)| *index >= 19 && matches!(character, '+' | '-'))
            .map(|(index, _)| index)
            .ok_or(KernelError::InvalidObservationTime)?;
        let (date_time, offset) = value.split_at(offset_index);
        let sign = if offset.starts_with('+') {
            1_i64
        } else {
            -1_i64
        };
        if offset.len() != 6 || offset.as_bytes()[3] != b':' {
            return Err(KernelError::InvalidObservationTime);
        }
        let hours = parse_digits(&offset[1..3])?;
        let minutes = parse_digits(&offset[4..6])?;
        if hours > 23 || minutes > 59 {
            return Err(KernelError::InvalidObservationTime);
        }
        (date_time, sign * i64::from(hours * 3600 + minutes * 60))
    };
    if date_time.len() < 19
        || &date_time[4..5] != "-"
        || &date_time[7..8] != "-"
        || &date_time[10..11] != "T"
        || &date_time[13..14] != ":"
        || &date_time[16..17] != ":"
    {
        return Err(KernelError::InvalidObservationTime);
    }
    let year = parse_digits(&date_time[0..4])? as i32;
    let month = parse_digits(&date_time[5..7])?;
    let day = parse_digits(&date_time[8..10])?;
    let hour = parse_digits(&date_time[11..13])?;
    let minute = parse_digits(&date_time[14..16])?;
    let second = parse_digits(&date_time[17..19])?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(KernelError::InvalidObservationTime);
    }
    // Fractional seconds may carry one through nine digits. Leap seconds and
    // timezone names are outside this closed RFC 3339 subset.
    let fraction = &date_time[19..];
    if !fraction.is_empty()
        && (!fraction.starts_with('.')
            || fraction.len() == 1
            || fraction.len() > 10
            || !fraction[1..].bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(KernelError::InvalidObservationTime);
    }
    // Match Go's RFC3339Nano formatting: nanosecond precision with trailing
    // fractional zeroes removed, including the decimal point when all zero.
    let fraction = fraction.trim_end_matches('0');
    let fraction = if fraction == "." { "" } else { fraction };
    let seconds = days_from_civil(year, month, day) * 86_400
        + i64::from(hour * 3600 + minute * 60 + second)
        - offset_seconds;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = seconds_of_day % 3600 / 60;
    let second = seconds_of_day % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{fraction}Z"
    ))
}

fn parse_digits(value: &str) -> Result<u32, KernelError> {
    // Fixed-width timestamp slices must contain ASCII digits only.
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(KernelError::InvalidObservationTime);
    }
    value
        .parse::<u32>()
        .map_err(|_| KernelError::InvalidObservationTime)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    // Gregorian leap-year rules apply to the admitted four-digit input year.
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    // Convert a Gregorian date to days relative to the Unix epoch using 400-year
    // eras; Euclidean division also behaves correctly before 1970.
    let adjusted_year = year - i32::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = i64::from(year_of_era) * 365 + i64::from(year_of_era / 4)
        - i64::from(year_of_era / 100)
        + day_of_year;
    i64::from(era) * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    // Inverse of `days_from_civil`, used after applying the numeric UTC offset.
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year as i32, month as u32, day as u32)
}

pub(super) fn attribute<'a>(event: &'a EventInput, key: &str) -> &'a str {
    // Decisions use trimmed views while the original ordered map remains intact
    // for input commitments and receipts.
    event.attributes.get(key).map_or("", |value| value.trim())
}

pub(super) fn scalar(value: &Option<CanonicalScalar>) -> &str {
    // Treat an absent optional provider scalar as empty for closed predicates.
    value.as_ref().map_or("", CanonicalScalar::as_str)
}

pub(super) fn first_non_empty<'a>(values: &[&'a str]) -> &'a str {
    // Preserve precedence in caller order and return a trimmed view of the first
    // usable identity or display field.
    values
        .iter()
        .copied()
        .find(|value| !value.trim().is_empty())
        .map_or("", str::trim)
}

pub(super) fn trim_empty(attributes: &mut BTreeMap<String, String>) {
    // Remove empty metadata without normalizing retained keys or values; their
    // exact strings remain part of the emitted finding JSON.
    attributes.retain(|key, value| !key.trim().is_empty() && !value.trim().is_empty());
}

pub(super) fn finding_hash(parts: &[&str]) -> String {
    // NUL-delimit trimmed components before hashing so field boundaries cannot
    // collide. The historical raw lowercase hex form is retained.
    let mut input = Vec::new();
    for part in parts {
        input.extend_from_slice(part.trim().as_bytes());
        input.push(0);
    }
    hex_digest(&sha256(&input))
}

pub(super) fn stable_external_id(value: &str) -> String {
    // Reject empty/control-bearing identity material, then expose only 128 digest
    // bits so provider identifiers do not pass through to stable rule output.
    let normalized = value.trim();
    if !valid_identity_component(normalized) {
        return String::new();
    }
    let digest = sha256(normalized.as_bytes());
    format!("id-{}", hex_digest(&digest[..16]))
}

pub(super) fn identity_anchor(attributes: &BTreeMap<String, String>, fields: &[&str]) -> String {
    // Every named field is required and emitted in caller order as `key=value`.
    // Any invalid name or value invalidates the whole recurrence anchor.
    if fields.is_empty() {
        return String::new();
    }
    let mut parts = Vec::with_capacity(fields.len());
    for field in fields {
        let field = field.trim();
        if field.is_empty() {
            return String::new();
        }
        let value = attributes.get(field).map_or("", |value| value.trim());
        if !valid_identity_component(value) {
            return String::new();
        }
        parts.push(format!("{field}={value}"));
    }
    parts.join("|")
}

pub(super) fn valid_identity_component(value: &str) -> bool {
    // Surrounding whitespace is tolerated by this predicate because callers
    // normalize before hashing; control characters are never identity material.
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

#[cfg(test)]
pub(super) fn byte_digest(value: &[u8]) -> String {
    hex_digest(&sha256(value))
}

fn hex_digest(value: &[u8]) -> String {
    // Manual lowercase encoding fixes one deterministic representation.
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn canonical_number(value: &str) -> Option<String> {
    // Preserve negative zero because Go's fixed-point formatting distinguishes it
    // from positive zero after parsing.
    if value.starts_with('-') && value.parse::<f64>().ok()? == 0.0 {
        return Some("-0".into());
    }
    // Go's `map[string]any` decoder materializes every JSON number as f64
    // before strconv.FormatFloat(value, 'f', -1, 64). Rust deliberately does
    // the same, including precision loss above 2^53.
    let value = value.parse::<f64>().ok()?;
    value.is_finite().then(|| fixed_decimal(value))
}

fn fixed_decimal(value: f64) -> String {
    // Rust's shortest representation may use scientific notation. Expand it to
    // fixed point to match Go's `FormatFloat(..., 'f', -1, 64)` contract.
    let shortest = value.to_string();
    let Some((mantissa, exponent)) = shortest
        .split_once('e')
        .or_else(|| shortest.split_once('E'))
    else {
        return shortest;
    };
    let exponent = exponent
        .parse::<i32>()
        .expect("f64 display always emits a valid decimal exponent");
    let (sign, unsigned) = mantissa
        .strip_prefix('-')
        .map_or(("", mantissa), |value| ("-", value));
    let decimal_index = unsigned.find('.').unwrap_or(unsigned.len()) as i32;
    let digits = unsigned.replace('.', "");
    let shifted = decimal_index + exponent;
    let fixed = if shifted <= 0 {
        format!("0.{}{}", "0".repeat((-shifted) as usize), digits)
    } else if shifted as usize >= digits.len() {
        format!("{}{}", digits, "0".repeat(shifted as usize - digits.len()))
    } else {
        let split = shifted as usize;
        format!("{}.{}", &digits[..split], &digits[split..])
    };
    format!("{sign}{fixed}")
}
