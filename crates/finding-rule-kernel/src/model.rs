use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Version of the bounded finding-rule request and authority receipt.
pub const SCHEMA_VERSION: &str = "cerebro.finding-rule-authority.v1";
/// Stable identifier of the first Rust-authoritative finding rule.
pub const TAILSCALE_RULE_ID: &str = "tailscale-tailnet-device-approval-disabled";
/// Generated policy-catalog digest for the exact Tailscale rule definition.
pub const TAILSCALE_DEFINITION_DIGEST: &str =
    "af1b1d2e11b9cc726ffe44a2d4c46e5e898e45c01da9e1b414fc2b6b56a09f8b";
/// Aurelius promoted-vulnerability rule identifier.
pub const AURELIUS_RULE_ID: &str = "aurelius-promoted-vulnerability-active";
/// Generated catalog digest for the exact Aurelius definition.
pub const AURELIUS_DEFINITION_DIGEST: &str =
    "5ec15d147ab34294d8214a19f519a7f52fce6bb2a59dfed9b408c3028695aab9";
/// Cosmo coordination-risk rule identifier.
pub const COSMO_RULE_ID: &str = "cosmo-coordination-active-risk";
/// Generated catalog digest for the exact Cosmo definition.
pub const COSMO_DEFINITION_DIGEST: &str =
    "1367f20b5cfe85e3f901760f27d8540d15227712b86e5ca3da41122e296225a4";

/// One supported finding-rule operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Evaluate one replayed event for a new or recurring finding.
    Evaluate,
    /// Derive the stable lifecycle anchor for an open finding.
    OpenAnchor,
    /// Evaluate one replayed event as a possible remediation close.
    Close,
}

/// Closed finding-rule input. Credentials and provider-owned scope are excluded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleRequest {
    /// Requested operation.
    pub operation: Operation,
    /// Exact rule identifier.
    pub rule_id: String,
    /// Trusted runtime identifier.
    pub runtime_id: String,
    /// Trusted runtime source identifier.
    pub runtime_source_id: String,
    /// Trusted runtime tenant identifier.
    pub runtime_tenant_id: String,
    /// Optional trusted application-workspace identifier.
    pub runtime_workspace_id: String,
    /// Replayed event identifier.
    pub event_id: String,
    /// Replayed event tenant identifier.
    pub event_tenant_id: String,
    /// Replayed event source identifier.
    pub event_source_id: String,
    /// Replayed event kind.
    pub event_kind: String,
    /// Closed event schema reference admitted by the trusted host.
    #[serde(default)]
    pub event_schema_ref: String,
    /// Replayed event occurrence time in RFC 3339 form.
    pub occurred_at: String,
    /// Host-supplied deterministic replay order for equal timestamps.
    #[serde(default)]
    pub replay_sequence: u64,
    /// Bounded normalized event or finding attributes.
    pub attributes: BTreeMap<String, String>,
    /// Original bounded provider payload represented as a JSON byte array.
    #[serde(default)]
    pub payload: Vec<u8>,
}

/// Content-bound request passed across the Wasm authority boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationEnvelope {
    /// Request schema version.
    pub schema_version: String,
    /// SHA-256 digest of the canonical request body.
    pub input_digest: String,
    /// Closed finding-rule request.
    pub request: RuleRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    None,
    Open,
    Close,
    OpenAnchor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ControlRef {
    pub(crate) framework_name: String,
    pub(crate) control_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct FindingRecord {
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

/// Rust authority result and immutable binding receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvaluationResponse {
    /// Response schema version.
    pub schema_version: &'static str,
    /// Exact evaluated rule.
    pub rule_id: &'static str,
    /// Digest of the generated Rust catalog definition.
    pub definition_digest: &'static str,
    /// Digest of the accepted request.
    pub input_digest: String,
    /// Digest of the decision fields.
    pub decision_digest: String,
    pub(crate) action: Action,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) anchor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) finding: Option<FindingRecord>,
}

/// Typed finding-rule rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KernelError {
    /// The request or response schema is not supported.
    UnsupportedSchema,
    /// The rule is not Rust-authoritative in this kernel.
    UnsupportedRule,
    /// The request digest does not bind the request body.
    InputDigestMismatch,
    /// Runtime and event scope do not identify the same tenant/workspace.
    ScopeMismatch,
    /// Trusted workspace scope did not match.
    WorkspaceMismatch,
    /// Event schema did not match the rule contract.
    SchemaMismatch,
    /// Action operations must not carry provider payload bytes.
    ActionPayloadNotEmpty,
    /// A required trusted host value was absent.
    MissingTrustedContext,
    /// Payload exceeded its byte budget.
    PayloadTooLarge,
    /// Payload exceeded its nesting budget.
    PayloadTooDeep,
    /// Payload exceeded its array-item budget.
    PayloadArrayTooLarge,
    /// Payload exceeded its object-field budget.
    PayloadObjectTooLarge,
    /// Payload exceeded its string budget.
    PayloadStringTooLarge,
    /// Payload repeated an object key.
    DuplicatePayloadField,
    /// Payload was malformed or outside the closed rule schema.
    MalformedPayload,
    /// Observation time was absent or malformed.
    InvalidObservationTime,
    /// Event attributes exceeded the closed host budget.
    InvalidAttributes,
    /// A required identity or timestamp is malformed.
    InvalidInput,
}
