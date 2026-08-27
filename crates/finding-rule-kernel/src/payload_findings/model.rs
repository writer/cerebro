use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub(crate) const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
pub(crate) const MAX_PAYLOAD_DEPTH: usize = 8;
pub(crate) const MAX_PAYLOAD_ARRAY_ITEMS: usize = 64;
pub(crate) const MAX_PAYLOAD_OBJECT_FIELDS: usize = 64;
pub(crate) const MAX_PAYLOAD_STRING_BYTES: usize = 8 * 1024;
const MAX_ATTRIBUTES: usize = 64;
const MAX_ATTRIBUTE_KEY_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    Evaluate,
    OpenAnchor,
    Close,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    None,
    Open,
    Close,
    OpenAnchor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TrustedRuntime {
    pub(crate) runtime_id: String,
    pub(crate) source_id: String,
    pub(crate) tenant_id: String,
    pub(crate) workspace_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EventInput {
    pub(crate) id: String,
    pub(crate) tenant_id: String,
    pub(crate) source_id: String,
    pub(crate) kind: String,
    pub(crate) schema_ref: String,
    /// Host-supplied observation time. Provider payload time fields are closed.
    pub(crate) observed_at: String,
    /// Host-supplied deterministic replay order for equal timestamps.
    pub(crate) replay_sequence: u64,
    pub(crate) attributes: BTreeMap<String, String>,
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuleRequest {
    pub(crate) operation: Operation,
    pub(crate) rule_id: String,
    pub(crate) runtime: TrustedRuntime,
    pub(crate) event: EventInput,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ControlRef {
    pub(crate) framework_name: String,
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
pub(crate) struct Decision {
    pub(crate) action: Action,
    pub(crate) anchor: String,
    pub(crate) finding: Option<RuleFindingDecision>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvaluatorOutput {
    pub(crate) decision: Decision,
    pub(crate) receipt: EvaluatorReceipt,
}

/// Trusted host scope carried alongside a raw rule decision.
///
/// Workspace is deliberately absent from the public finding identity and raw
/// rule record. The shared adapter must retain this envelope through candidate
/// evaluation, upsert, and closeout so storage can enforce workspace scope.
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

impl ScopedDecision {
    pub(crate) fn require_workspace(&self, workspace_id: &str) -> Result<&Decision, KernelError> {
        if workspace_id.trim().is_empty() || self.workspace_id != workspace_id.trim() {
            return Err(KernelError::WorkspaceMismatch);
        }
        Ok(&self.decision)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PersistencePath {
    Candidate,
    ProductionUpsert,
    Closeout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

impl ScopedDecision {
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

impl Default for HostFindingFields {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct CompleteFindingRecord {
    #[serde(flatten)]
    pub(crate) rule: RuleFindingDecision,
    #[serde(flatten)]
    pub(crate) host: HostFindingFields,
}

impl From<RuleFindingDecision> for CompleteFindingRecord {
    fn from(rule: RuleFindingDecision) -> Self {
        Self {
            rule,
            host: HostFindingFields::default(),
        }
    }
}

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
    pub(super) fn none() -> Self {
        Self {
            action: Action::None,
            anchor: String::new(),
            finding: None,
        }
    }

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

    pub(super) fn open(finding: RuleFindingDecision) -> Self {
        Self {
            action: Action::Open,
            anchor: String::new(),
            finding: Some(finding),
        }
    }

    pub(super) fn close(anchor: String) -> Self {
        Self {
            action: Action::Close,
            anchor,
            finding: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum KernelError {
    UnsupportedRule,
    UnsupportedOperation,
    ScopeMismatch,
    WorkspaceMismatch,
    SchemaMismatch,
    ActionPayloadNotEmpty,
    MissingTrustedContext,
    EvaluatorFailure,
    MalformedEvaluatorResponse,
    InvalidEvaluatorReceipt,
    PayloadTooLarge,
    PayloadTooDeep,
    PayloadArrayTooLarge,
    PayloadObjectTooLarge,
    PayloadStringTooLarge,
    DuplicatePayloadField,
    MalformedPayload,
    InvalidObservationTime,
    InvalidAttributes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CanonicalScalar(String);

impl CanonicalScalar {
    pub(super) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for CanonicalScalar {
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
    if runtime.runtime_id.trim().is_empty()
        || runtime.tenant_id.trim().is_empty()
        || runtime.source_id.trim().is_empty()
        || runtime.workspace_id.trim().is_empty()
        || event.id.trim().is_empty()
        || event.tenant_id.trim().is_empty()
    {
        return Err(KernelError::MissingTrustedContext);
    }
    if runtime.tenant_id.trim() != event.tenant_id.trim()
        || !runtime.source_id.trim().eq_ignore_ascii_case(source_id)
        || !event.source_id.trim().eq_ignore_ascii_case(source_id)
    {
        return Err(KernelError::ScopeMismatch);
    }
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
    if payload.is_empty() {
        return Ok(T::default());
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(KernelError::PayloadTooLarge);
    }
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
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let decoded = T::deserialize(&mut deserializer).map_err(|_| KernelError::MalformedPayload)?;
    deserializer
        .end()
        .map_err(|_| KernelError::MalformedPayload)?;
    Ok(decoded)
}

#[derive(Clone, Copy)]
enum BudgetFailure {
    Depth,
    Array,
    Object,
    String,
    Duplicate,
}

struct BoundedValueSeed<'a> {
    depth: usize,
    failure: &'a Cell<Option<BudgetFailure>>,
}

impl<'a, 'de> DeserializeSeed<'de> for BoundedValueSeed<'a> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
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
    depth: usize,
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

pub(super) fn normalized_observation_time(value: &str) -> Result<String, KernelError> {
    let parsed = OffsetDateTime::parse(value.trim(), &Rfc3339)
        .map_err(|_| KernelError::InvalidObservationTime)?;
    parsed
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| KernelError::InvalidObservationTime)
}

pub(super) fn attribute<'a>(event: &'a EventInput, key: &str) -> &'a str {
    event.attributes.get(key).map_or("", |value| value.trim())
}

pub(super) fn scalar(value: &Option<CanonicalScalar>) -> &str {
    value.as_ref().map_or("", CanonicalScalar::as_str)
}

pub(super) fn first_non_empty<'a>(values: &[&'a str]) -> &'a str {
    values
        .iter()
        .copied()
        .find(|value| !value.trim().is_empty())
        .map_or("", str::trim)
}

pub(super) fn trim_empty(attributes: &mut BTreeMap<String, String>) {
    attributes.retain(|key, value| !key.trim().is_empty() && !value.trim().is_empty());
}

pub(super) fn finding_hash(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.trim().as_bytes());
        digest.update([0]);
    }
    hex_digest(&digest.finalize())
}

pub(super) fn stable_external_id(value: &str) -> String {
    let normalized = value.trim();
    if !valid_identity_component(normalized) {
        return String::new();
    }
    let digest = Sha256::digest(normalized.as_bytes());
    format!("id-{}", hex_digest(&digest[..16]))
}

pub(super) fn identity_anchor(attributes: &BTreeMap<String, String>, fields: &[&str]) -> String {
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
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

pub(super) fn byte_digest(value: &[u8]) -> String {
    hex_digest(&Sha256::digest(value))
}

fn hex_digest(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn canonical_number(value: &str) -> Option<String> {
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
