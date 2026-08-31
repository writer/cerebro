#![deny(unsafe_code)]

//! Provider-neutral wire contracts for black-box Slack agent evaluation.
//!
//! This crate deliberately contains no model client, holdout content, credentials,
//! runtime adapter, or environment route. Candidate and evaluator processes can
//! share protocol records without sharing private evaluation state.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Schema tag for candidate turn requests and candidate turn outcomes.
pub const AGENT_TURN_REQUEST_V1: &str = "agent-turn-request/v1";
/// Schema tag for a transport-confirmed candidate delivery.
pub const AGENT_DELIVERY_RECEIPT_V1: &str = "agent-delivery-receipt/v1";
/// Schema tag for the complete private v1 supervisor episode input.
pub const SUPERVISOR_EPISODE_V1: &str = "slack-agent-supervisor-episode/v1";
/// Schema tag for a v1 private operator turn.
pub const OPERATOR_TURN_V1: &str = "slack-agent-operator-turn/v1";
/// Schema tag for a completed v1 black-box episode receipt.
pub const BLACKBOX_RECEIPT_V1: &str = "slack-agent-blackbox-receipt/v1";
/// Schema tag for a content-blinded v1 grading packet.
pub const BLIND_PACKET_V1: &str = "slack-agent-blind-packet/v1";
/// Schema tag for a v1 grade bound to one blind packet.
pub const BLIND_GRADE_V1: &str = "slack-agent-blind-grade/v1";
/// Schema tag for a sealed v2 episode manifest.
pub const SEALED_EPISODE_MANIFEST_V2: &str = "slack-agent-sealed-episode-manifest/v2";
/// Schema tag for a deterministic v2 episode event program.
pub const EPISODE_EVENT_PROGRAM_V2: &str = "slack-agent-episode-event-program/v2";
/// Schema tag for a v2 supervisor execution receipt.
pub const SUPERVISOR_EXECUTION_RECEIPT_V2: &str = "slack-agent-supervisor-execution-receipt/v2";
/// Schema tag for a signed v2 receipt wrapper.
pub const SIGNED_RECEIPT_ENVELOPE_V2: &str = "slack-agent-signed-receipt-envelope/v2";
/// Schema tag for a v2 authoritative-fact receipt.
pub const AUTHORITATIVE_FACT_RECEIPT_V2: &str = "slack-agent-authoritative-fact-receipt/v2";
/// Schema tag for a v2 authoritative-action receipt.
pub const AUTHORITATIVE_ACTION_RECEIPT_V2: &str = "slack-agent-authoritative-action-receipt/v2";
/// Schema tag for a v2 operator-decision receipt.
pub const OPERATOR_DECISION_RECEIPT_V2: &str = "slack-agent-operator-decision-receipt/v2";
/// Schema tag for a v2 packet that blinds candidate answer content.
pub const CONTENT_BLIND_PACKET_V2: &str = "slack-agent-content-blind-packet/v2";
/// Schema tag for a v2 packet that exposes only gradeable evidence bindings.
pub const EVIDENCE_BLIND_PACKET_V2: &str = "slack-agent-evidence-blind-packet/v2";
/// Schema tag for a v2 packet that exposes only operational behavior.
pub const OPERATIONAL_BLIND_PACKET_V2: &str = "slack-agent-operational-blind-packet/v2";
/// Schema tag for a sealed v2 evaluation-suite manifest.
pub const SEALED_SUITE_MANIFEST_V2: &str = "slack-agent-sealed-suite-manifest/v2";
/// Schema tag for evaluator-private v2 holdout assignments.
pub const SEALED_HOLDOUT_ASSIGNMENTS_V2: &str = "slack-agent-sealed-holdout-assignments/v2";
/// Schema tag for the public commitment to sealed holdout assignments.
pub const HOLDOUT_ASSIGNMENT_COMMITMENT_V2: &str = "slack-agent-holdout-assignment-commitment/v2";
/// Schema tag for the join from a holdout assignment to its execution.
pub const ASSIGNMENT_EXECUTION_BINDING_V2: &str = "slack-agent-assignment-execution-binding/v2";
/// Schema tag for the distinct principals participating in execution.
pub const EXECUTION_PRINCIPALS_V2: &str = "slack-agent-execution-principals/v2";
/// Schema tag for machine-evaluated v2 criteria.
pub const DETERMINISTIC_CRITERIA_RECEIPT_V2: &str = "slack-agent-deterministic-criteria-receipt/v2";
/// Schema tag for a v2 grade produced by an independent principal.
pub const INDEPENDENT_GRADE_RECEIPT_V2: &str = "slack-agent-independent-grade-receipt/v2";
/// Schema tag for sealed v2 promotion requirements.
pub const PROMOTION_POLICY_V2: &str = "slack-agent-promotion-policy/v2";
/// Schema tag for the v2 aggregation of promotion evidence.
pub const PROMOTION_AGGREGATION_RECEIPT_V2: &str = "slack-agent-promotion-aggregation-receipt/v2";
/// Schema tag for binding evaluation evidence to an exact source head.
pub const EXACT_HEAD_BINDING_V2: &str = "slack-agent-exact-head-binding/v2";
/// Schema tag for randomized v2 baseline assignment evidence.
pub const RANDOMIZED_BASELINE_ASSIGNMENT_V2: &str = "slack-agent-randomized-baseline-assignment/v2";
/// Schema tag for an authenticated v2 Slack canary result.
pub const SLACK_CANARY_RECEIPT_V2: &str = "slack-agent-slack-canary-receipt/v2";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Candidate-visible input for one Slack-agent turn.
///
/// This is a wire shape, not an authorization result. Hosts must validate the
/// schema tag, tenant and actor bindings, timestamps, bounds, and any effect
/// authorization before execution. Unknown fields are rejected during decoding.
pub struct CandidateTurnRequest {
    /// Wire schema expected to equal [`AGENT_TURN_REQUEST_V1`].
    pub schema_version: String,
    /// Tenant label supplied by the host boundary.
    pub tenant_id: String,
    /// Correlation identity for this candidate turn.
    pub request_id: String,
    /// Slack thread or equivalent conversation reference.
    pub thread_ref: String,
    /// Optional scope shared by related conversations.
    #[serde(default)]
    pub context_scope_ref: Option<String>,
    /// Candidate-visible identity of the requesting actor.
    pub actor_ref: String,
    /// Host-formatted authority time for the assessment.
    pub assessment_at: String,
    /// Current user message presented to the candidate.
    pub message: String,
    /// Prior messages in chronological host order.
    #[serde(default)]
    pub history: Vec<ConversationMessage>,
    /// Optional metadata aligned by index with `history` by host convention.
    #[serde(default)]
    pub history_metadata: Vec<ConversationMessageMetadata>,
    /// Candidate working memory restored from an earlier turn, when any.
    pub working_state: Option<Value>,
    /// Explicit effect grants available to this exact request.
    #[serde(default)]
    pub effect_authorizations: Vec<EffectAuthorization>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// One candidate-visible conversation message.
pub struct ConversationMessage {
    /// Host-defined speaker role.
    pub role: String,
    /// Exact message content.
    pub content: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Optional host metadata for one prior conversation message.
pub struct ConversationMessageMetadata {
    /// Stable actor reference when the host can supply one.
    #[serde(default)]
    pub actor_ref: Option<String>,
    /// Transport message identity when available.
    #[serde(default)]
    pub message_ref: Option<String>,
    /// Host-formatted receive time when available.
    #[serde(default)]
    pub received_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Host-issued authority for one exact candidate tool effect.
///
/// Every contextual coordinate and the canonical input digest travels with the
/// approval so an executor can reject replay against another request or tool.
pub struct EffectAuthorization {
    /// Durable approval record reference.
    pub approval_ref: String,
    /// Tenant for which the effect was approved.
    pub tenant_id: String,
    /// Candidate request authorized to use the effect.
    pub request_id: String,
    /// Conversation in which approval was granted.
    pub thread_ref: String,
    /// Actor whose authority approved the effect.
    pub actor_ref: String,
    /// Exact tool operation authorized.
    pub tool_id: String,
    /// Digest of the authorized canonical tool input.
    pub input_digest: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
/// Candidate result for one turn before or after transport delivery.
///
/// The tagged variants keep content generation, approval requests, intentional
/// ignores, and transport delivery as distinct observable states.
pub enum CandidateTurnOutcome {
    /// Candidate produced content that a host must still deliver.
    PendingDelivery {
        /// Outcome schema expected to equal [`AGENT_TURN_REQUEST_V1`].
        schema_version: String,
        /// Candidate execution lane used for the result.
        lane: String,
        /// Slack-formatted content awaiting transport.
        markdown: String,
        /// Candidate-defined terminal state label.
        final_state: String,
        /// Evidence references supporting the content.
        evidence_refs: Vec<String>,
        /// Number of tools invoked during the turn.
        tool_call_count: usize,
        /// Working memory offered to a subsequent turn.
        working_state: Option<Value>,
    },
    /// Candidate content already delivered by the candidate runtime.
    Delivered {
        /// Outcome schema expected to equal [`AGENT_TURN_REQUEST_V1`].
        schema_version: String,
        /// Candidate execution lane used for the result.
        lane: String,
        /// Slack-formatted delivered content.
        markdown: String,
        /// Candidate-defined terminal state label.
        final_state: String,
        /// Evidence references supporting the content.
        evidence_refs: Vec<String>,
        /// Number of tools invoked during the turn.
        tool_call_count: usize,
        /// Working memory offered to a subsequent turn.
        working_state: Option<Value>,
    },
    /// Candidate stopped before an effect that requires external approval.
    ApprovalRequired {
        /// Outcome schema expected to equal [`AGENT_TURN_REQUEST_V1`].
        schema_version: String,
        /// Candidate execution lane that requested approval.
        lane: String,
        /// Provider-neutral structured approval request.
        request: Value,
        /// Number of tools invoked before the approval boundary.
        tool_call_count: usize,
    },
    /// Candidate intentionally produced no response or effect.
    Ignored {
        /// Outcome schema expected to equal [`AGENT_TURN_REQUEST_V1`].
        schema_version: String,
    },
}

impl CandidateTurnOutcome {
    /// Returns delivered or pending markdown without cloning it.
    #[must_use]
    pub fn markdown(&self) -> Option<&str> {
        match self {
            Self::PendingDelivery { markdown, .. } | Self::Delivered { markdown, .. } => {
                Some(markdown)
            }
            Self::ApprovalRequired { .. } | Self::Ignored { .. } => None,
        }
    }

    /// Returns whether the host still owes a transport delivery.
    #[must_use]
    pub const fn needs_delivery(&self) -> bool {
        matches!(self, Self::PendingDelivery { .. })
    }

    /// Projects lane, terminal-state, and tool-count telemetry uniformly.
    ///
    /// Approval outcomes have no terminal state, while ignored turns have no
    /// lane and count no tool calls under this projection.
    #[must_use]
    pub fn telemetry(&self) -> (Option<&str>, Option<&str>, usize) {
        match self {
            Self::PendingDelivery {
                lane,
                final_state,
                tool_call_count,
                ..
            }
            | Self::Delivered {
                lane,
                final_state,
                tool_call_count,
                ..
            } => (Some(lane), Some(final_state), *tool_call_count),
            Self::ApprovalRequired {
                lane,
                tool_call_count,
                ..
            } => (Some(lane), None, *tool_call_count),
            Self::Ignored { .. } => (None, None, 0),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Transport evidence that pending candidate content was delivered.
pub struct CandidateDeliveryReceipt {
    /// Wire schema expected to equal [`AGENT_DELIVERY_RECEIPT_V1`].
    pub schema_version: String,
    /// Tenant copied from the delivered turn.
    pub tenant_id: String,
    /// Conversation that received the content.
    pub thread_ref: String,
    /// Candidate request whose content was delivered.
    pub request_id: String,
    /// Transport implementation that performed delivery.
    pub transport: String,
    /// Provider receipt or message reference for the delivery.
    pub delivery_ref: String,
    /// Digest of the exact delivered payload.
    pub payload_digest: String,
    /// Host-formatted delivery completion time.
    pub delivered_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Resource and timing bounds for a v1 supervised episode.
pub struct EpisodeLimits {
    /// Maximum candidate/operator exchanges.
    pub max_exchanges: usize,
    /// Candidate-turn deadline in milliseconds.
    pub turn_timeout_ms: u64,
    /// Operator-turn deadline in milliseconds.
    pub operator_timeout_ms: u64,
    /// Additional maximum latency keyed by candidate lane.
    pub lane_latency_limits_ms: BTreeMap<String, u64>,
    /// Optional exchange after which the harness restarts the candidate.
    #[serde(default)]
    pub restart_after_exchange: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Evaluator-private state used to drive a supervised episode.
pub struct PrivateEpisodeContext {
    /// Structured instructions available only to the operator controller.
    pub operator_brief: Value,
    /// Opaque reference to the simulated or controlled world.
    pub world_ref: String,
    /// Digest binding the exact starting world state.
    pub world_digest: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Complete v1 input for a private black-box supervisor run.
pub struct SupervisorEpisodeSpec {
    /// Wire schema expected to equal [`SUPERVISOR_EPISODE_V1`].
    pub schema_version: String,
    /// Stable episode correlation reference.
    pub episode_ref: String,
    /// State withheld from the candidate runtime.
    pub private_context: PrivateEpisodeContext,
    /// First candidate-visible request.
    pub initial_turn: CandidateTurnRequest,
    /// Closed resource and timing bounds.
    pub limits: EpisodeLimits,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// One normalized turn in a supervisor-visible transcript.
pub struct TranscriptTurn {
    /// Speaker role assigned by the harness.
    pub role: String,
    /// Exact visible message.
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Candidate-reported runtime identity and build state.
///
/// This record is an attestation payload; cryptographic or deployment-level
/// verification belongs to the host that admits it into evaluation evidence.
pub struct CandidateRuntimeAttestation {
    /// Runtime attestation schema selected by the host.
    pub schema_version: String,
    /// Whether startup checks reported the candidate ready.
    pub agent_ready: bool,
    /// Source commit claimed by the runtime build.
    pub build_commit_sha: String,
    /// Whether the runtime claims its source tree was clean.
    pub build_tree_clean: bool,
    /// Identity of the concrete candidate process or service instance.
    pub runtime_instance_ref: String,
    /// Model provider when the candidate discloses one.
    pub model_provider: Option<String>,
    /// Model identifier when the candidate discloses one.
    pub model_id: Option<String>,
    /// Digest of model configuration when available.
    pub model_config_sha256: Option<String>,
    /// Candidate session protocol version.
    pub session_schema_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Artifact and runtime identity for the evaluated candidate.
pub struct CandidateAttestation {
    /// Evaluator-facing candidate reference.
    pub candidate_ref: String,
    /// Digest of the evaluated candidate artifact.
    pub artifact_digest: String,
    /// Runtime instance and build attestation.
    pub runtime: CandidateRuntimeAttestation,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Full request/outcome receipt for one candidate exchange.
pub struct ExchangeReceipt {
    /// One-based or host-defined episode sequence number.
    pub sequence: usize,
    /// Digest of the exact candidate request.
    pub request_digest: String,
    /// Digest of the exact candidate outcome.
    pub response_digest: String,
    /// Runtime instance that executed the turn.
    pub runtime_instance_ref: String,
    /// Host-formatted start time.
    pub started_at: String,
    /// Host-formatted completion time.
    pub completed_at: String,
    /// Measured wall-clock latency in milliseconds.
    pub latency_ms: u64,
    /// Candidate-visible request committed by `request_digest`.
    pub request: CandidateTurnRequest,
    /// Candidate outcome committed by `response_digest`.
    pub outcome: CandidateTurnOutcome,
    /// Transport receipt when the outcome was delivered.
    pub delivery: Option<CandidateDeliveryReceipt>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Private request asking the operator controller how to continue an episode.
pub struct OperatorTurnRequest {
    /// Wire schema expected to equal [`OPERATOR_TURN_V1`].
    pub schema_version: String,
    /// Episode being controlled.
    pub episode_ref: String,
    /// Evaluator-private instructions and world binding.
    pub private_context: PrivateEpisodeContext,
    /// Supervisor-visible transcript through the latest exchange.
    pub transcript: Vec<TranscriptTurn>,
    /// Most recent candidate request/outcome evidence.
    pub latest_exchange: ExchangeReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
/// Operator-controller decision after inspecting one exchange.
pub enum OperatorDecision {
    /// Send another user message to the candidate.
    Continue {
        /// Next candidate-visible message.
        message: String,
        /// Private explanation for continuing.
        reason: String,
    },
    /// End the episode because its evaluation objective is complete.
    Conclude {
        /// Private explanation for the conclusion.
        reason: String,
    },
    /// Stop the episode because continuing would be invalid or unsafe.
    Abort {
        /// Private explanation for the abort.
        reason: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Machine-detected episode defect independent of subjective grading.
pub struct DeterministicDefect {
    /// Stable defect classification.
    pub code: String,
    /// Bounded or host-formatted diagnostic detail.
    pub detail: String,
    /// Whether the defect invalidates further episode execution or grading.
    pub terminal: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Aggregate measurements produced by the evaluation harness.
pub struct HarnessTelemetry {
    /// Number of completed exchanges.
    pub exchange_count: usize,
    /// Sum of measured candidate latency in milliseconds.
    pub total_latency_ms: u64,
    /// Sum of candidate tool calls across exchanges.
    pub tool_call_count: usize,
    /// Whether the configured restart boundary was exercised.
    pub restart_observed: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Complete v1 black-box evidence for one finished episode.
pub struct BlackboxReceipt {
    /// Wire schema expected to equal [`BLACKBOX_RECEIPT_V1`].
    pub schema_version: String,
    /// Episode correlation reference.
    pub episode_ref: String,
    /// Candidate artifact and runtime identity.
    pub candidate: CandidateAttestation,
    /// Digest of private context without exposing its content separately.
    pub private_context_digest: String,
    /// Supervisor-visible conversation transcript.
    pub transcript: Vec<TranscriptTurn>,
    /// Ordered request/outcome evidence for every exchange.
    pub exchanges: Vec<ExchangeReceipt>,
    /// Aggregate harness measurements.
    pub telemetry: HarnessTelemetry,
    /// Objective defects observed by the harness.
    pub deterministic_defects: Vec<DeterministicDefect>,
    /// Host-formatted episode completion time.
    pub completed_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Payload paired with its canonical JSON content digest.
///
/// The envelope detects modification but provides no signer identity or
/// authenticity. Use a signed receipt envelope when provenance must be proven.
pub struct DigestEnvelope<T> {
    /// Serializable value committed by the digest.
    pub payload: T,
    /// `sha256:` digest of recursively key-sorted JSON for `payload`.
    pub payload_digest: String,
}

impl<T: Serialize> DigestEnvelope<T> {
    /// Canonicalizes and seals a serializable payload.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error when `payload` cannot be represented.
    pub fn new(payload: T) -> Result<Self, serde_json::Error> {
        let payload_digest = sha256_json(&payload)?;
        Ok(Self {
            payload,
            payload_digest,
        })
    }

    /// Recomputes the payload digest and reports exact string equality.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error when the in-memory payload cannot be
    /// represented for canonical hashing.
    pub fn verify_digest(&self) -> Result<bool, serde_json::Error> {
        Ok(self.payload_digest == sha256_json(&self.payload)?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Candidate-anonymized transcript turn exposed to a grader.
pub struct BlindTranscriptTurn {
    /// Blinded speaker role.
    pub role: String,
    /// Gradeable visible content.
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// V1 grading packet stripped of direct candidate identity.
pub struct BlindPacket {
    /// Wire schema expected to equal [`BLIND_PACKET_V1`].
    pub schema_version: String,
    /// Assignment identity shared with the resulting grade.
    pub assignment_ref: String,
    /// Evaluator-issued candidate pseudonym.
    pub candidate_alias: String,
    /// Gradeable brief without evaluator-private holdout mapping.
    pub evaluation_brief: Value,
    /// Candidate-anonymized transcript.
    pub transcript: Vec<BlindTranscriptTurn>,
    /// Objective harness measurements.
    pub telemetry: HarnessTelemetry,
    /// Objective defects available to the grader.
    pub deterministic_defects: Vec<DeterministicDefect>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// V1 independent grade bound to one exact blind packet.
pub struct BlindGrade {
    /// Wire schema expected to equal [`BLIND_GRADE_V1`].
    pub schema_version: String,
    /// Assignment copied from the packet.
    pub assignment_ref: String,
    /// Canonical digest of the graded packet.
    pub packet_digest: String,
    /// Digest identifying the grader without exposing its direct identity.
    pub grader_identity_digest: String,
    /// Six normalized scores in the inclusive range `0..=100`.
    pub scores: BlindScores,
    /// Whether the grader found a defect that invalidates the episode.
    pub terminal_defect: bool,
    /// Grader explanation for the scores and terminal decision.
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// V1 rubric scores, each expressed as an integer percentage.
pub struct BlindScores {
    /// Practical value of the response to the user.
    pub human_usefulness: u8,
    /// Discipline in grounding claims and effects in evidence.
    pub evidence_discipline: u8,
    /// Appropriate proactive progress toward the task.
    pub initiative: u8,
    /// Continuity across turns, restarts, and working state.
    pub continuity: u8,
    /// Reduction in operator follow-up and manual coordination.
    pub burden_reduction: u8,
    /// Respect for approval, tenant, and effect boundaries.
    pub bounded_authority: u8,
}

impl BlindGrade {
    /// Validates packet identity, digest integrity, and score bounds.
    ///
    /// This check does not authenticate the grader or assess rationale quality.
    ///
    /// # Errors
    ///
    /// Returns a stable diagnostic string when the grade does not bind the
    /// supplied packet or any score exceeds 100. Serialization errors from
    /// packet verification are rendered into the returned string.
    pub fn validate_for(&self, packet: &DigestEnvelope<BlindPacket>) -> Result<(), String> {
        if self.schema_version != BLIND_GRADE_V1
            || self.assignment_ref != packet.payload.assignment_ref
            || self.packet_digest != packet.payload_digest
            || !packet.verify_digest().map_err(|error| error.to_string())?
        {
            return Err("blind grade does not bind the exact assignment packet".into());
        }
        if [
            self.scores.human_usefulness,
            self.scores.evidence_discipline,
            self.scores.initiative,
            self.scores.continuity,
            self.scores.burden_reduction,
            self.scores.bounded_authority,
        ]
        .iter()
        .any(|score| *score > 100)
        {
            return Err("blind grade score is outside 0..=100".into());
        }
        Ok(())
    }
}

/// Returns a canonical, recursively key-sorted JSON SHA-256 digest.
///
/// Object key order is normalized at every depth; array order and scalar JSON
/// representations remain significant. The result uses a `sha256:` prefix.
///
/// # Errors
///
/// Returns a JSON error if the value cannot be converted or serialized.
pub fn sha256_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    let bytes = serde_json::to_vec(&canonicalize(value))?;
    Ok(sha256_bytes(&bytes))
}

/// Returns the SHA-256 digest of the exact UTF-8 bytes in `value`.
#[must_use]
pub fn sha256_text(value: &str) -> String {
    sha256_bytes(value.as_bytes())
}

fn sha256_bytes(value: &[u8]) -> String {
    // Lowercase hexadecimal plus an algorithm prefix gives every wire digest one
    // self-describing textual representation.
    let digest = Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{digest}")
}

fn canonicalize(value: Value) -> Value {
    // Sort object keys recursively because input may contain arbitrary nested
    // `Value` fields. Preserve arrays because their order is protocol content.
    match value {
        Value::Object(object) => {
            let mut entries = object.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, canonicalize(value)))
                    .collect::<Map<_, _>>(),
            )
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        other => other,
    }
}

/// The complete private episode commitment. Its canonical digest binds every
/// input that can change the meaning or difficulty of an episode.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedEpisodeManifestV2 {
    pub schema_version: String,
    pub manifest_ref: String,
    pub scenario_digest: String,
    pub generator: SurfaceGeneratorAttestationV2,
    pub program: EpisodeEventProgramV2,
    pub limits: EpisodeLimitsV2,
    pub world_digest: String,
    pub operator_controller: OperatorControllerAttestationV2,
    pub candidate_surface_contract_digest: String,
}

impl SealedEpisodeManifestV2 {
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        sha256_json(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceGeneratorAttestationV2 {
    pub generator_ref: String,
    pub artifact_digest: String,
    pub semantic_template_digest: String,
    pub surface_seed_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeLimitsV2 {
    pub max_events: usize,
    pub max_candidate_turns: usize,
    pub candidate_turn_timeout_ms: u64,
    pub operator_turn_timeout_ms: u64,
    pub episode_timeout_ms: u64,
    pub phase_latency_limits_ms: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteFamilyRequirementV2 {
    pub family_ref: String,
    pub minimum_episode_count: usize,
    pub minimum_surface_variant_count: usize,
    pub minimum_sample_count_per_variant: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteEpisodeBindingV2 {
    pub episode_manifest_digest: String,
    pub family_ref: String,
    pub semantic_template_ref: String,
    pub surface_variant_ref: String,
    pub sample_index: usize,
    pub comparison_pair_ref: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedSuiteManifestV2 {
    pub schema_version: String,
    pub suite_ref: String,
    pub corpus_digest: String,
    pub suite_generator_digest: String,
    pub episode_bindings: Vec<SuiteEpisodeBindingV2>,
    pub family_requirements: Vec<SuiteFamilyRequirementV2>,
    pub assignment_policy_digest: String,
    pub promotion_policy_digest: String,
}

impl SealedSuiteManifestV2 {
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        sha256_json(self)
    }

    pub fn validate_coverage(&self) -> Result<(), String> {
        if self.schema_version != SEALED_SUITE_MANIFEST_V2
            || self.suite_ref.trim().is_empty()
            || self.episode_bindings.is_empty()
            || self.family_requirements.is_empty()
        {
            return Err("sealed suite manifest is incomplete".into());
        }
        let family_refs = self
            .family_requirements
            .iter()
            .map(|requirement| requirement.family_ref.as_str())
            .collect::<BTreeSet<_>>();
        if family_refs.len() != self.family_requirements.len()
            || self.family_requirements.iter().any(|requirement| {
                requirement.family_ref.trim().is_empty()
                    || requirement.minimum_episode_count == 0
                    || requirement.minimum_surface_variant_count == 0
                    || requirement.minimum_sample_count_per_variant == 0
            })
        {
            return Err("suite family requirements must be unique and non-zero".into());
        }
        let episode_digests = self
            .episode_bindings
            .iter()
            .map(|binding| binding.episode_manifest_digest.as_str())
            .collect::<BTreeSet<_>>();
        if episode_digests.len() != self.episode_bindings.len()
            || self
                .episode_bindings
                .iter()
                .any(|binding| !family_refs.contains(binding.family_ref.as_str()))
        {
            return Err(
                "suite episode bindings are duplicate or reference an undeclared family".into(),
            );
        }
        for requirement in &self.family_requirements {
            let bindings = self
                .episode_bindings
                .iter()
                .filter(|binding| binding.family_ref == requirement.family_ref)
                .collect::<Vec<_>>();
            let variants = bindings
                .iter()
                .map(|binding| binding.surface_variant_ref.as_str())
                .collect::<BTreeSet<_>>();
            if bindings.len() < requirement.minimum_episode_count
                || variants.len() < requirement.minimum_surface_variant_count
                || variants.iter().any(|variant| {
                    bindings
                        .iter()
                        .filter(|binding| binding.surface_variant_ref == *variant)
                        .count()
                        < requirement.minimum_sample_count_per_variant
                })
            {
                return Err(format!(
                    "suite family {} does not meet its sealed coverage requirement",
                    requirement.family_ref
                ));
            }
        }
        Ok(())
    }
}

/// Evaluator-private mapping. `blinding_nonce` must never be placed in a
/// candidate request, blind packet, or candidate image.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedHoldoutAssignmentsV2 {
    pub schema_version: String,
    pub suite_manifest_digest: String,
    pub blinding_nonce: String,
    pub assignments: Vec<PrivateHoldoutAssignmentV2>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHoldoutAssignmentV2 {
    pub assignment_ref: String,
    pub assignment_alias: String,
    pub episode_manifest_digest: String,
    pub candidate_attestation_digest: String,
    pub candidate_alias: String,
    pub run_index: usize,
    pub presentation_order: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutAssignmentCommitmentV2 {
    pub schema_version: String,
    pub suite_manifest_digest: String,
    pub assignment_count: usize,
    pub sealed_assignment_manifest_digest: String,
}

impl SealedHoldoutAssignmentsV2 {
    pub fn validate_and_commit(&self) -> Result<HoldoutAssignmentCommitmentV2, String> {
        if self.schema_version != SEALED_HOLDOUT_ASSIGNMENTS_V2
            || self.suite_manifest_digest.trim().is_empty()
            || self.blinding_nonce.len() < 32
            || self.assignments.is_empty()
        {
            return Err("sealed holdout assignments are incomplete".into());
        }
        let assignment_refs = self
            .assignments
            .iter()
            .map(|assignment| assignment.assignment_ref.as_str())
            .collect::<BTreeSet<_>>();
        let assignment_aliases = self
            .assignments
            .iter()
            .map(|assignment| assignment.assignment_alias.as_str())
            .collect::<BTreeSet<_>>();
        let presentation_orders = self
            .assignments
            .iter()
            .map(|assignment| assignment.presentation_order)
            .collect::<BTreeSet<_>>();
        if assignment_refs.len() != self.assignments.len()
            || assignment_aliases.len() != self.assignments.len()
            || presentation_orders.len() != self.assignments.len()
        {
            return Err("holdout assignment identities, aliases, and order must be unique".into());
        }
        let sealed_assignment_manifest_digest =
            sha256_json(self).map_err(|error| error.to_string())?;
        Ok(HoldoutAssignmentCommitmentV2 {
            schema_version: HOLDOUT_ASSIGNMENT_COMMITMENT_V2.into(),
            suite_manifest_digest: self.suite_manifest_digest.clone(),
            assignment_count: self.assignments.len(),
            sealed_assignment_manifest_digest,
        })
    }
}

/// Evaluator-private, supervisor-signed join between one committed holdout
/// assignment and the exact execution receipt produced for it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentExecutionBindingV2 {
    pub schema_version: String,
    pub holdout_assignment_commitment_digest: String,
    pub assignment_alias: String,
    pub episode_manifest_digest: String,
    pub candidate_attestation_digest: String,
    pub execution_receipt_digest: String,
    pub comparison_pair_ref: String,
    pub sample_index: usize,
    pub run_index: usize,
    pub presentation_order: usize,
}

impl AssignmentExecutionBindingV2 {
    pub fn validate_shape(&self, commitment_digest: &str) -> Result<(), String> {
        if self.schema_version != ASSIGNMENT_EXECUTION_BINDING_V2
            || self.holdout_assignment_commitment_digest != commitment_digest
            || self.assignment_alias.trim().is_empty()
            || self.episode_manifest_digest.trim().is_empty()
            || self.candidate_attestation_digest.trim().is_empty()
            || self.execution_receipt_digest.trim().is_empty()
            || self.comparison_pair_ref.trim().is_empty()
        {
            return Err(
                "assignment execution binding is incomplete or commitment-mismatched".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeEventProgramV2 {
    pub schema_version: String,
    pub program_ref: String,
    pub events: Vec<ProgrammedEventV2>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProgrammedEventV2 {
    Message {
        event_ref: String,
        thread_alias: String,
        actor_alias: String,
        message: String,
        at: String,
    },
    Correction {
        event_ref: String,
        thread_alias: String,
        actor_alias: String,
        replaces_event_ref: String,
        message: String,
        at: String,
    },
    OpenThread {
        event_ref: String,
        thread_alias: String,
        context_scope_alias: String,
        actor_alias: String,
        message: String,
        at: String,
    },
    ChangeWorld {
        event_ref: String,
        mutation_ref: String,
        world_before_digest: String,
        world_after_digest: String,
        at: String,
    },
    Restart {
        event_ref: String,
        target: RestartTargetV2,
        at: String,
    },
    Wake {
        event_ref: String,
        thread_alias: String,
        commitment_alias: String,
        occurrence_alias: String,
        at: String,
    },
    Authorize {
        event_ref: String,
        thread_alias: String,
        actor_alias: String,
        approval_alias: String,
        tool_id: String,
        input_digest: String,
        at: String,
    },
    AdvanceClock {
        event_ref: String,
        from: String,
        to: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartTargetV2 {
    CandidateRuntime,
    SessionStoreConnection,
}

/// Candidate-visible identifiers must resemble the normal Slack contract and
/// must not carry stable evaluator vocabulary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateVisibleAliasesV2 {
    pub tenant_id: String,
    pub request_id: String,
    pub thread_ref: String,
    pub actor_ref: String,
    pub context_scope_ref: Option<String>,
    pub delivery_ref: String,
}

impl CandidateVisibleAliasesV2 {
    pub fn validate(&self) -> Result<(), String> {
        let values = [
            self.tenant_id.as_str(),
            self.request_id.as_str(),
            self.thread_ref.as_str(),
            self.actor_ref.as_str(),
            self.context_scope_ref.as_deref().unwrap_or_default(),
            self.delivery_ref.as_str(),
        ];
        if values.iter().any(|value| value.trim().is_empty()) {
            return Err("candidate-visible aliases must be non-empty".into());
        }
        let forbidden = ["blackbox", "eval", "holdout", "scenario", "candidate"];
        if values.iter().any(|value| {
            let normalized = value.to_ascii_lowercase();
            forbidden.iter().any(|marker| normalized.contains(marker))
        }) {
            return Err("candidate-visible aliases disclose evaluator state".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorControllerAttestationV2 {
    pub controller_ref: String,
    pub artifact_digest: String,
    pub policy_digest: String,
    pub principal_ref: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePrincipalAttestationV2 {
    pub principal_ref: String,
    pub artifact_digest: String,
    pub endpoint_identity_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPrincipalsV2 {
    pub schema_version: String,
    pub supervisor: RuntimePrincipalAttestationV2,
    pub candidate: RuntimePrincipalAttestationV2,
    pub operator: RuntimePrincipalAttestationV2,
    pub world_controller: RuntimePrincipalAttestationV2,
}

impl ExecutionPrincipalsV2 {
    pub fn validate_separation(&self) -> Result<(), String> {
        if self.schema_version != EXECUTION_PRINCIPALS_V2 {
            return Err("unsupported execution principal schema".into());
        }
        let principals = [
            &self.supervisor,
            &self.candidate,
            &self.operator,
            &self.world_controller,
        ];
        if principals.iter().any(|principal| {
            principal.principal_ref.trim().is_empty()
                || principal.artifact_digest.trim().is_empty()
                || principal.endpoint_identity_digest.trim().is_empty()
        }) {
            return Err("execution principal attestation is incomplete".into());
        }
        let principal_refs = principals
            .iter()
            .map(|principal| principal.principal_ref.as_str())
            .collect::<BTreeSet<_>>();
        let endpoint_identities = principals
            .iter()
            .map(|principal| principal.endpoint_identity_digest.as_str())
            .collect::<BTreeSet<_>>();
        if principal_refs.len() != principals.len() || endpoint_identities.len() != principals.len()
        {
            return Err(
                "candidate, operator, supervisor, and world controller must be distinct".into(),
            );
        }
        Ok(())
    }

    pub fn validate_grader_separation(&self, grader_principal_ref: &str) -> Result<(), String> {
        if grader_principal_ref.trim().is_empty()
            || [
                self.supervisor.principal_ref.as_str(),
                self.candidate.principal_ref.as_str(),
                self.operator.principal_ref.as_str(),
                self.world_controller.principal_ref.as_str(),
            ]
            .contains(&grader_principal_ref)
        {
            return Err("grader principal is not independent of episode execution".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CriterionStatusV2 {
    Unsatisfied,
    Satisfied,
    Impossible,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorCriterionStateV2 {
    pub criterion_ref: String,
    pub status: CriterionStatusV2,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CriterionEvaluationKindV2 {
    AuthoritativeFact,
    AuthoritativeAction,
    ConversationOutcome,
    AuthorityBoundary,
    PersistenceRecall,
    LatencyBudget,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorCriterionDefinitionV2 {
    pub criterion_ref: String,
    pub evaluation_kind: CriterionEvaluationKindV2,
    pub rule_digest: String,
    pub required_evidence_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CriterionTransitionV2 {
    pub criterion_ref: String,
    pub before: CriterionStatusV2,
    pub after: CriterionStatusV2,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicCriteriaReceiptV2 {
    pub schema_version: String,
    pub criteria_policy_digest: String,
    pub operator_request_digest: String,
    pub definitions: Vec<OperatorCriterionDefinitionV2>,
    pub before_snapshot_digest: String,
    pub after_snapshot_digest: String,
    pub transitions: Vec<CriterionTransitionV2>,
}

impl DeterministicCriteriaReceiptV2 {
    pub fn validate_against(
        &self,
        before: &[OperatorCriterionStateV2],
        after: &[OperatorCriterionStateV2],
    ) -> Result<(), String> {
        if self.schema_version != DETERMINISTIC_CRITERIA_RECEIPT_V2
            || self.criteria_policy_digest.trim().is_empty()
            || self.operator_request_digest.trim().is_empty()
            || self.before_snapshot_digest
                != sha256_json(&before).map_err(|error| error.to_string())?
            || self.after_snapshot_digest
                != sha256_json(&after).map_err(|error| error.to_string())?
        {
            return Err("deterministic criteria receipt is incomplete or digest-mismatched".into());
        }
        let before_by_ref = before
            .iter()
            .map(|criterion| (criterion.criterion_ref.as_str(), criterion))
            .collect::<BTreeMap<_, _>>();
        let after_by_ref = after
            .iter()
            .map(|criterion| (criterion.criterion_ref.as_str(), criterion))
            .collect::<BTreeMap<_, _>>();
        if before_by_ref.len() != before.len() || after_by_ref.len() != after.len() {
            return Err("criteria snapshots contain duplicate references".into());
        }
        let definitions = self
            .definitions
            .iter()
            .map(|definition| (definition.criterion_ref.as_str(), definition))
            .collect::<BTreeMap<_, _>>();
        if definitions.len() != self.definitions.len()
            || definitions.keys().copied().collect::<BTreeSet<_>>()
                != before_by_ref.keys().copied().collect::<BTreeSet<_>>()
            || definitions.keys().copied().collect::<BTreeSet<_>>()
                != after_by_ref.keys().copied().collect::<BTreeSet<_>>()
        {
            return Err("criteria definitions do not exactly cover both snapshots".into());
        }
        let transitions = self
            .transitions
            .iter()
            .map(|transition| (transition.criterion_ref.as_str(), transition))
            .collect::<BTreeMap<_, _>>();
        if transitions.len() != self.transitions.len() || transitions.len() != definitions.len() {
            return Err("criteria transitions must cover every criterion exactly once".into());
        }
        for (criterion_ref, definition) in definitions {
            let before = before_by_ref[criterion_ref];
            let after = after_by_ref[criterion_ref];
            let transition = transitions[criterion_ref];
            if transition.before != before.status
                || transition.after != after.status
                || transition.evidence_refs != after.evidence_refs
                || (after.status == CriterionStatusV2::Satisfied
                    && transition.evidence_refs.len() < definition.required_evidence_count)
            {
                return Err(format!(
                    "criterion {criterion_ref} transition is not deterministically supported"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorDispositionV2 {
    Continue,
    Conclude,
    Abort,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorDecisionReceiptV2 {
    pub schema_version: String,
    pub episode_manifest_digest: String,
    pub sequence: usize,
    pub operator_request_digest: String,
    pub controller: OperatorControllerAttestationV2,
    pub criteria_receipt_digest: String,
    pub criteria_before: Vec<OperatorCriterionStateV2>,
    pub disposition: OperatorDispositionV2,
    pub emitted_event: Option<ProgrammedEventV2>,
    pub criteria_after: Vec<OperatorCriterionStateV2>,
    pub reason_code: String,
    pub decided_at: String,
}

impl OperatorDecisionReceiptV2 {
    pub fn validate_semantics(&self) -> Result<(), String> {
        if self.schema_version != OPERATOR_DECISION_RECEIPT_V2
            || self.criteria_receipt_digest.trim().is_empty()
        {
            return Err("unsupported operator decision receipt schema".into());
        }
        let before = criterion_refs(&self.criteria_before)?;
        let after = criterion_refs(&self.criteria_after)?;
        if before != after || after.is_empty() {
            return Err("operator criteria must be non-empty and stable across a decision".into());
        }
        match self.disposition {
            OperatorDispositionV2::Continue if self.emitted_event.is_none() => {
                Err("a continue decision must emit the next sealed event".into())
            }
            OperatorDispositionV2::Conclude
                if self.emitted_event.is_some()
                    || self
                        .criteria_after
                        .iter()
                        .any(|criterion| criterion.status != CriterionStatusV2::Satisfied) =>
            {
                Err("conclusion requires every criterion satisfied and no next event".into())
            }
            OperatorDispositionV2::Abort if self.emitted_event.is_some() => {
                Err("an abort decision cannot emit a candidate event".into())
            }
            _ => Ok(()),
        }
    }
}

fn criterion_refs(criteria: &[OperatorCriterionStateV2]) -> Result<BTreeSet<&str>, String> {
    let refs = criteria
        .iter()
        .map(|criterion| criterion.criterion_ref.as_str())
        .collect::<BTreeSet<_>>();
    if refs.len() != criteria.len() || refs.iter().any(|criterion_ref| criterion_ref.is_empty()) {
        return Err("operator criterion references must be unique and non-empty".into());
    }
    Ok(refs)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritativeEvidenceStateV2 {
    Observed,
    NotObserved,
    Partial,
    Failed,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeFactReceiptV2 {
    pub schema_version: String,
    pub observation_ref: String,
    pub world_instance_ref: String,
    pub subject_ref: String,
    pub predicate: String,
    pub value: Value,
    pub state: AuthoritativeEvidenceStateV2,
    pub complete: bool,
    pub source_ref: String,
    pub source_revision: String,
    pub observed_at: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritativeActionStateV2 {
    Rejected,
    Applied,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeActionReceiptV2 {
    pub schema_version: String,
    pub action_ref: String,
    pub world_instance_ref: String,
    pub actor_principal_ref: String,
    pub authority_ref: String,
    pub tool_id: String,
    pub input_digest: String,
    pub state: AuthoritativeActionStateV2,
    pub result_digest: String,
    pub verification_observation_refs: Vec<String>,
    pub occurred_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerAttestationV2 {
    pub principal_ref: String,
    pub algorithm: SignatureAlgorithmV2,
    pub key_ref: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithmV2 {
    AwsKmsEcdsaSha256,
    Ed25519,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReceiptEnvelopeV2<T> {
    pub schema_version: String,
    pub payload: T,
    pub payload_digest: String,
    pub signer: SignerAttestationV2,
    pub signature_base64: String,
}

impl<T: Serialize> SignedReceiptEnvelopeV2<T> {
    pub fn signing_payload_digest(payload: &T) -> Result<String, serde_json::Error> {
        sha256_json(payload)
    }

    pub fn validate_digest_and_signature_shape(&self) -> Result<(), String> {
        if self.schema_version != SIGNED_RECEIPT_ENVELOPE_V2
            || self.payload_digest
                != Self::signing_payload_digest(&self.payload).map_err(|error| error.to_string())?
            || self.signer.principal_ref.trim().is_empty()
            || self.signer.key_ref.trim().is_empty()
            || self.signature_base64.trim().is_empty()
        {
            return Err("signed receipt envelope is incomplete or digest-mismatched".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPromotionDispositionV2 {
    IneligiblePendingIndependentGrades,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorExecutionReceiptV2 {
    pub schema_version: String,
    pub episode_manifest_digest: String,
    pub candidate_attestation_digest: String,
    pub operator_decisions: Vec<OperatorDecisionReceiptV2>,
    pub fact_receipt_digests: Vec<String>,
    pub action_receipt_digests: Vec<String>,
    pub transcript_digest: String,
    pub deterministic_defects: Vec<DeterministicDefect>,
    pub promotion_disposition: ExecutionPromotionDispositionV2,
    pub completed_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindTaskBriefV2 {
    pub operator_request: String,
    pub success_definition: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentBlindPacketV2 {
    pub schema_version: String,
    pub assignment_alias: String,
    pub candidate_alias: String,
    pub task: BlindTaskBriefV2,
    pub transcript: Vec<BlindTranscriptTurn>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateClaimV2 {
    pub claim_ref: String,
    pub text: String,
    pub cited_observation_refs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindAuthoritativeFactV2 {
    pub observation_alias: String,
    pub subject_alias: String,
    pub predicate: String,
    pub value: Value,
    pub state: AuthoritativeEvidenceStateV2,
    pub complete: bool,
    pub observed_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindAuthoritativeActionV2 {
    pub action_alias: String,
    pub actor_alias: String,
    pub authority_alias: String,
    pub tool_alias: String,
    pub input_digest: String,
    pub state: AuthoritativeActionStateV2,
    pub verification_observation_aliases: Vec<String>,
    pub occurred_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBlindPacketV2 {
    pub schema_version: String,
    pub assignment_alias: String,
    pub candidate_alias: String,
    pub task: BlindTaskBriefV2,
    pub claims: Vec<CandidateClaimV2>,
    pub authoritative_facts: Vec<BlindAuthoritativeFactV2>,
    pub authoritative_actions: Vec<BlindAuthoritativeActionV2>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhaseV2 {
    Ingress,
    SessionLoad,
    LeaseAcquire,
    Route,
    Operate,
    Tool,
    Critique,
    Present,
    Journal,
    Render,
    Deliver,
    RestartRecovery,
    Operator,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseOutcomeV2 {
    Completed,
    TimedOut,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseTimingReceiptV2 {
    pub exchange_sequence: usize,
    pub phase: ExecutionPhaseV2,
    pub attempt: usize,
    pub started_at: String,
    pub completed_at: String,
    pub duration_ms: u64,
    pub budget_ms: u64,
    pub input_digest: String,
    pub output_digest: Option<String>,
    pub outcome: PhaseOutcomeV2,
    pub model_call_count: usize,
    pub tool_call_count: usize,
    pub repair_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangePhaseTelemetryV2 {
    pub exchange_sequence: usize,
    pub end_to_end_ms: u64,
    pub accounted_phase_ms: u64,
    pub unaccounted_overhead_ms: u64,
    pub phases: Vec<PhaseTimingReceiptV2>,
}

impl ExchangePhaseTelemetryV2 {
    pub fn validate_accounting(&self) -> Result<(), String> {
        let measured = self.phases.iter().try_fold(0_u64, |total, phase| {
            if phase.exchange_sequence != self.exchange_sequence
                || phase.attempt == 0
                || phase.budget_ms == 0
                || phase.input_digest.trim().is_empty()
                || phase.duration_ms > phase.budget_ms && phase.outcome == PhaseOutcomeV2::Completed
            {
                return Err("phase timing receipt is incomplete or violates its budget".to_owned());
            }
            total
                .checked_add(phase.duration_ms)
                .ok_or_else(|| "phase duration accounting overflowed".to_owned())
        })?;
        if measured != self.accounted_phase_ms
            || self
                .accounted_phase_ms
                .checked_add(self.unaccounted_overhead_ms)
                != Some(self.end_to_end_ms)
        {
            return Err("phase timing does not account for the exchange end to end".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalBlindPacketV2 {
    pub schema_version: String,
    pub assignment_alias: String,
    pub candidate_alias: String,
    pub exchanges: Vec<ExchangePhaseTelemetryV2>,
    pub deterministic_defects: Vec<DeterministicDefect>,
    pub burden: InteractionBurdenReceiptV2,
    pub restart_count: usize,
    pub delivered_exchange_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InteractionBurdenReceiptV2 {
    pub operator_message_count: usize,
    pub clarification_request_count: usize,
    pub repeated_read_count: usize,
    pub model_call_count: usize,
    pub tool_call_count: usize,
    pub repair_loop_count: usize,
    pub retry_count: usize,
    pub unresolved_handoff_count: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlindPacketKindV2 {
    Content,
    Evidence,
    Operational,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(
    tag = "packet_kind",
    content = "packet",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum MaterializedBlindPacketV2 {
    Content(ContentBlindPacketV2),
    Evidence(EvidenceBlindPacketV2),
    Operational(OperationalBlindPacketV2),
}

impl MaterializedBlindPacketV2 {
    pub fn packet_kind(&self) -> BlindPacketKindV2 {
        match self {
            Self::Content(_) => BlindPacketKindV2::Content,
            Self::Evidence(_) => BlindPacketKindV2::Evidence,
            Self::Operational(_) => BlindPacketKindV2::Operational,
        }
    }

    pub fn assignment_alias(&self) -> &str {
        match self {
            Self::Content(packet) => &packet.assignment_alias,
            Self::Evidence(packet) => &packet.assignment_alias,
            Self::Operational(packet) => &packet.assignment_alias,
        }
    }

    pub fn candidate_alias(&self) -> &str {
        match self {
            Self::Content(packet) => &packet.candidate_alias,
            Self::Evidence(packet) => &packet.candidate_alias,
            Self::Operational(packet) => &packet.candidate_alias,
        }
    }

    pub fn payload_digest(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::Content(packet) => sha256_json(packet),
            Self::Evidence(packet) => sha256_json(packet),
            Self::Operational(packet) => sha256_json(packet),
        }
    }

    pub fn validate_grade_binding(&self, grade: &IndependentGradeReceiptV2) -> Result<(), String> {
        let (schema_version, payload) = match self {
            Self::Content(packet) => (packet.schema_version.as_str(), serde_json::to_value(packet)),
            Self::Evidence(packet) => {
                (packet.schema_version.as_str(), serde_json::to_value(packet))
            }
            Self::Operational(packet) => {
                (packet.schema_version.as_str(), serde_json::to_value(packet))
            }
        };
        let expected_schema_version = match self.packet_kind() {
            BlindPacketKindV2::Content => CONTENT_BLIND_PACKET_V2,
            BlindPacketKindV2::Evidence => EVIDENCE_BLIND_PACKET_V2,
            BlindPacketKindV2::Operational => OPERATIONAL_BLIND_PACKET_V2,
        };
        if schema_version != expected_schema_version
            || self.assignment_alias().trim().is_empty()
            || self.candidate_alias().trim().is_empty()
        {
            return Err("materialized blind packet is incomplete or schema-mismatched".into());
        }
        if grade.packet_kind != self.packet_kind()
            || grade.assignment_alias != self.assignment_alias()
            || grade.packet_digest != self.payload_digest().map_err(|error| error.to_string())?
        {
            return Err("independent grade does not bind the exact materialized packet".into());
        }
        let payload = payload.map_err(|error| error.to_string())?;
        if grade.citations.iter().any(|citation| {
            !citation.packet_item_ref.starts_with('/')
                || payload.pointer(&citation.packet_item_ref).is_none()
        }) {
            return Err(
                "independent grade citation does not resolve in the bound materialized packet"
                    .into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GradeDimensionV2 {
    HumanUsefulness,
    EvidenceDiscipline,
    Initiative,
    Continuity,
    BurdenReduction,
    BoundedAuthority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionScoreV2 {
    pub dimension: GradeDimensionV2,
    pub score: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GradeCitationV2 {
    pub dimension: GradeDimensionV2,
    pub packet_item_ref: String,
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraderAttestationV2 {
    pub principal_ref: String,
    pub artifact_digest: String,
    pub rubric_digest: String,
    pub calibration_receipt_digest: String,
    pub calibration_passed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentGradeReceiptV2 {
    pub schema_version: String,
    pub grade_ref: String,
    pub suite_manifest_digest: String,
    pub assignment_alias: String,
    pub packet_kind: BlindPacketKindV2,
    pub packet_digest: String,
    pub grader: GraderAttestationV2,
    pub scores: Vec<DimensionScoreV2>,
    pub hard_defect_codes: Vec<String>,
    pub citations: Vec<GradeCitationV2>,
    pub graded_at: String,
}

impl IndependentGradeReceiptV2 {
    pub fn validate(
        &self,
        principals: &ExecutionPrincipalsV2,
        required_dimensions: &[GradeDimensionV2],
    ) -> Result<(), String> {
        principals.validate_grader_separation(&self.grader.principal_ref)?;
        if self.schema_version != INDEPENDENT_GRADE_RECEIPT_V2
            || self.grade_ref.trim().is_empty()
            || self.assignment_alias.trim().is_empty()
            || self.packet_digest.trim().is_empty()
            || !self.grader.calibration_passed
            || self.grader.artifact_digest.trim().is_empty()
            || self.grader.rubric_digest.trim().is_empty()
            || self.grader.calibration_receipt_digest.trim().is_empty()
        {
            return Err("independent grade receipt is incomplete or uncalibrated".into());
        }
        let score_dimensions = self
            .scores
            .iter()
            .map(|score| score.dimension)
            .collect::<BTreeSet<_>>();
        let required_dimensions = required_dimensions.iter().copied().collect::<BTreeSet<_>>();
        if score_dimensions.len() != self.scores.len()
            || score_dimensions != required_dimensions
            || self.scores.iter().any(|score| score.score > 100)
        {
            return Err("grade scores do not exactly cover the required dimensions".into());
        }
        let cited_dimensions = self
            .citations
            .iter()
            .map(|citation| citation.dimension)
            .collect::<BTreeSet<_>>();
        if cited_dimensions != required_dimensions
            || self.citations.iter().any(|citation| {
                citation.packet_item_ref.trim().is_empty() || citation.rationale.trim().is_empty()
            })
        {
            return Err("every grade dimension requires packet-bound evidence".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactHeadBindingV2 {
    pub schema_version: String,
    pub suite_manifest_digest: String,
    pub commit_sha: String,
    pub artifact_digest: String,
    pub build_tree_clean: bool,
    pub hosted_checks_receipt_digest: String,
}

impl ExactHeadBindingV2 {
    pub fn validate(&self, suite_manifest_digest: &str) -> Result<(), String> {
        if self.schema_version != EXACT_HEAD_BINDING_V2
            || self.suite_manifest_digest != suite_manifest_digest
            || self.commit_sha.len() != 40
            || !self.commit_sha.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.artifact_digest.trim().is_empty()
            || !self.build_tree_clean
            || self.hosted_checks_receipt_digest.trim().is_empty()
        {
            return Err(
                "promotion is not bound to one clean exact head and hosted check receipt".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RandomizedBaselineAssignmentV2 {
    pub schema_version: String,
    pub holdout_assignment_commitment_digest: String,
    pub randomization_algorithm: String,
    pub randomization_seed_commitment: String,
    pub order_balance_digest: String,
    pub candidate_alias: String,
    pub baseline_alias: String,
}

impl RandomizedBaselineAssignmentV2 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != RANDOMIZED_BASELINE_ASSIGNMENT_V2
            || self.holdout_assignment_commitment_digest.trim().is_empty()
            || self.randomization_algorithm.trim().is_empty()
            || self.randomization_seed_commitment.trim().is_empty()
            || self.order_balance_digest.trim().is_empty()
            || self.candidate_alias.trim().is_empty()
            || self.baseline_alias.trim().is_empty()
            || self.candidate_alias == self.baseline_alias
        {
            return Err("baseline comparison is not independently randomized and blinded".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SlackCanaryReceiptV2 {
    pub schema_version: String,
    pub exact_head_artifact_digest: String,
    pub allowed_channel_scope_digest: String,
    pub request_digest: String,
    pub delivered_response_digest: String,
    pub runtime_attestation_digest: String,
    pub passed: bool,
    pub observed_at: String,
}

impl SlackCanaryReceiptV2 {
    pub fn validate(&self, exact_head: &ExactHeadBindingV2) -> Result<(), String> {
        if self.schema_version != SLACK_CANARY_RECEIPT_V2
            || self.exact_head_artifact_digest != exact_head.artifact_digest
            || self.allowed_channel_scope_digest.trim().is_empty()
            || self.request_digest.trim().is_empty()
            || self.delivered_response_digest.trim().is_empty()
            || self.runtime_attestation_digest.trim().is_empty()
            || !self.passed
        {
            return Err("real Slack canary did not pass on the exact evaluated artifact".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionPolicyV2 {
    pub schema_version: String,
    pub required_dimensions: Vec<GradeDimensionV2>,
    pub dimension_packet_kinds: BTreeMap<GradeDimensionV2, BlindPacketKindV2>,
    pub required_family_refs: Vec<String>,
    pub minimum_independent_graders_per_assignment: usize,
    pub minimum_dimension_score: u8,
    pub minimum_mean_score_basis_points: u16,
    pub minimum_family_pass_rate_basis_points: u16,
    pub minimum_paired_lower_bound_basis_points: i32,
    pub confidence_level_basis_points: u16,
    pub maximum_repair_loops_per_assignment: usize,
    pub maximum_retries_per_assignment: usize,
    pub maximum_repeated_reads_per_assignment: usize,
}

impl PromotionPolicyV2 {
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        sha256_json(self)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != PROMOTION_POLICY_V2
            || self.required_dimensions.is_empty()
            || self.required_family_refs.is_empty()
            || self.minimum_independent_graders_per_assignment < 2
            || self.minimum_dimension_score > 100
            || self.minimum_mean_score_basis_points > 10_000
            || self.minimum_family_pass_rate_basis_points > 10_000
            || !(5_000..10_000).contains(&self.confidence_level_basis_points)
            || self
                .required_dimensions
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != self.required_dimensions.len()
            || self
                .dimension_packet_kinds
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != self
                    .required_dimensions
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>()
            || self
                .required_family_refs
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.required_family_refs.len()
        {
            return Err("promotion policy is incomplete, duplicate, or out of range".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentPromotionResultV2 {
    pub assignment_alias: String,
    pub family_ref: String,
    pub grade_refs: Vec<String>,
    pub mean_score_basis_points: u16,
    pub hard_defect_count: usize,
    pub burden: InteractionBurdenReceiptV2,
    pub burden_receipt_digest: String,
    pub passed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyPromotionResultV2 {
    pub family_ref: String,
    pub assignment_count: usize,
    pub passed_assignment_count: usize,
    pub pass_rate_basis_points: u16,
    pub passed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairedComparisonResultV2 {
    pub comparison_pair_ref: String,
    pub sample_count: usize,
    pub mean_delta_basis_points: i32,
    pub lower_confidence_bound_basis_points: i32,
    pub confidence_level_basis_points: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionDecisionV2 {
    Ineligible,
    Rejected,
    EligibleForPromotionDecision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionAggregationReceiptV2 {
    pub schema_version: String,
    pub suite_manifest_digest: String,
    pub promotion_policy_digest: String,
    pub exact_head: ExactHeadBindingV2,
    pub randomized_baseline: RandomizedBaselineAssignmentV2,
    pub slack_canary: SlackCanaryReceiptV2,
    pub assignment_execution_binding_digests: Vec<String>,
    pub execution_receipt_digests: Vec<String>,
    pub execution_terminal_defect_count: usize,
    pub independent_grade_digests: Vec<String>,
    pub assignment_results: Vec<AssignmentPromotionResultV2>,
    pub family_results: Vec<FamilyPromotionResultV2>,
    pub paired_comparisons: Vec<PairedComparisonResultV2>,
    pub decision: PromotionDecisionV2,
    pub blockers: Vec<String>,
    pub aggregated_at: String,
}

impl PromotionAggregationReceiptV2 {
    pub fn validate_against(
        &self,
        suite: &SealedSuiteManifestV2,
        policy: &PromotionPolicyV2,
        principals: &ExecutionPrincipalsV2,
        grades: &[IndependentGradeReceiptV2],
    ) -> Result<(), String> {
        suite.validate_coverage()?;
        policy.validate()?;
        principals.validate_separation()?;
        if self.schema_version != PROMOTION_AGGREGATION_RECEIPT_V2
            || self.suite_manifest_digest != suite.digest().map_err(|error| error.to_string())?
            || self.promotion_policy_digest != policy.digest().map_err(|error| error.to_string())?
        {
            return Err("promotion aggregation is not bound to the sealed suite and policy".into());
        }
        self.exact_head.validate(&self.suite_manifest_digest)?;
        self.randomized_baseline.validate()?;
        self.slack_canary.validate(&self.exact_head)?;
        if self.assignment_execution_binding_digests.is_empty()
            || self
                .assignment_execution_binding_digests
                .iter()
                .any(String::is_empty)
            || self
                .assignment_execution_binding_digests
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.assignment_execution_binding_digests.len()
        {
            return Err("promotion aggregation has no unique assignment execution bindings".into());
        }
        if self.execution_receipt_digests.is_empty()
            || self.execution_receipt_digests.iter().any(String::is_empty)
            || self
                .execution_receipt_digests
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.execution_receipt_digests.len()
        {
            return Err("promotion aggregation has no bound execution receipts".into());
        }
        let grade_refs = grades
            .iter()
            .map(|grade| grade.grade_ref.as_str())
            .collect::<BTreeSet<_>>();
        if grade_refs.len() != grades.len() {
            return Err("independent grade references must be unique".into());
        }
        for grade in grades {
            if grade.suite_manifest_digest != self.suite_manifest_digest {
                return Err("grade belongs to another sealed suite".into());
            }
            let dimensions = policy
                .dimension_packet_kinds
                .iter()
                .filter_map(|(dimension, packet_kind)| {
                    (*packet_kind == grade.packet_kind).then_some(*dimension)
                })
                .collect::<Vec<_>>();
            grade.validate(principals, &dimensions)?;
        }
        let expected_grade_digests = grades
            .iter()
            .map(sha256_json)
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|error| error.to_string())?;
        if expected_grade_digests
            != self
                .independent_grade_digests
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        {
            return Err("promotion aggregation omits or substitutes an independent grade".into());
        }
        self.validate_assignment_results(policy, grades)?;
        self.validate_family_results(policy)?;
        let paired_passed = !self.paired_comparisons.is_empty()
            && self.paired_comparisons.iter().all(|comparison| {
                comparison.sample_count > 0
                    && comparison.confidence_level_basis_points
                        == policy.confidence_level_basis_points
                    && comparison.lower_confidence_bound_basis_points
                        >= policy.minimum_paired_lower_bound_basis_points
            });
        let eligible = self.assignment_results.iter().all(|result| result.passed)
            && self.family_results.iter().all(|result| result.passed)
            && paired_passed
            && self.execution_terminal_defect_count == 0
            && self.blockers.is_empty();
        if (self.decision == PromotionDecisionV2::EligibleForPromotionDecision) != eligible {
            return Err("promotion decision does not match its deterministic aggregate".into());
        }
        Ok(())
    }

    fn validate_assignment_results(
        &self,
        policy: &PromotionPolicyV2,
        grades: &[IndependentGradeReceiptV2],
    ) -> Result<(), String> {
        let aliases = self
            .assignment_results
            .iter()
            .map(|result| result.assignment_alias.as_str())
            .collect::<BTreeSet<_>>();
        let grade_aliases = grades
            .iter()
            .map(|grade| grade.assignment_alias.as_str())
            .collect::<BTreeSet<_>>();
        if aliases.len() != self.assignment_results.len() || aliases != grade_aliases {
            return Err("assignment promotion results must be unique".into());
        }
        for result in &self.assignment_results {
            let assignment_grades = grades
                .iter()
                .filter(|grade| grade.assignment_alias == result.assignment_alias)
                .collect::<Vec<_>>();
            let refs = assignment_grades
                .iter()
                .map(|grade| grade.grade_ref.as_str())
                .collect::<BTreeSet<_>>();
            let score_count = assignment_grades
                .iter()
                .map(|grade| grade.scores.len())
                .sum::<usize>();
            let score_total = assignment_grades
                .iter()
                .flat_map(|grade| grade.scores.iter())
                .try_fold(0_u64, |total, score| {
                    total.checked_add(u64::from(score.score))
                })
                .ok_or_else(|| "grade score total overflowed".to_owned())?;
            let mean_score_basis_points = if score_count == 0 {
                0
            } else {
                u16::try_from(score_total.saturating_mul(100) / score_count as u64)
                    .map_err(|_| "grade mean is outside basis-point range".to_owned())?
            };
            let hard_defect_count = assignment_grades
                .iter()
                .map(|grade| grade.hard_defect_codes.len())
                .sum::<usize>();
            let enough_independent_graders = policy.required_dimensions.iter().all(|dimension| {
                assignment_grades
                    .iter()
                    .filter(|grade| {
                        grade
                            .scores
                            .iter()
                            .any(|score| score.dimension == *dimension)
                    })
                    .map(|grade| grade.grader.principal_ref.as_str())
                    .collect::<BTreeSet<_>>()
                    .len()
                    >= policy.minimum_independent_graders_per_assignment
            });
            let passed = enough_independent_graders
                && hard_defect_count == 0
                && !result.burden_receipt_digest.trim().is_empty()
                && mean_score_basis_points >= policy.minimum_mean_score_basis_points
                && result.burden.repair_loop_count <= policy.maximum_repair_loops_per_assignment
                && result.burden.retry_count <= policy.maximum_retries_per_assignment
                && result.burden.repeated_read_count
                    <= policy.maximum_repeated_reads_per_assignment
                && assignment_grades.iter().all(|grade| {
                    grade
                        .scores
                        .iter()
                        .all(|score| score.score >= policy.minimum_dimension_score)
                });
            if refs != result.grade_refs.iter().map(String::as_str).collect()
                || result.mean_score_basis_points != mean_score_basis_points
                || result.hard_defect_count != hard_defect_count
                || result.passed != passed
            {
                return Err(format!(
                    "assignment {} aggregate is not reproducible from its grades",
                    result.assignment_alias
                ));
            }
        }
        Ok(())
    }

    fn validate_family_results(&self, policy: &PromotionPolicyV2) -> Result<(), String> {
        let family_results = self
            .family_results
            .iter()
            .map(|result| (result.family_ref.as_str(), result))
            .collect::<BTreeMap<_, _>>();
        if family_results.len() != self.family_results.len()
            || family_results.keys().copied().collect::<BTreeSet<_>>()
                != policy
                    .required_family_refs
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>()
        {
            return Err("family results do not exactly cover the promotion policy".into());
        }
        for (family_ref, result) in family_results {
            let assignments = self
                .assignment_results
                .iter()
                .filter(|assignment| assignment.family_ref == family_ref)
                .collect::<Vec<_>>();
            let passed_assignment_count = assignments
                .iter()
                .filter(|assignment| assignment.passed)
                .count();
            let pass_rate_basis_points = if assignments.is_empty() {
                0
            } else {
                u16::try_from(passed_assignment_count.saturating_mul(10_000) / assignments.len())
                    .map_err(|_| "family pass rate is outside basis-point range".to_owned())?
            };
            let passed = !assignments.is_empty()
                && pass_rate_basis_points >= policy.minimum_family_pass_rate_basis_points;
            if result.assignment_count != assignments.len()
                || result.passed_assignment_count != passed_assignment_count
                || result.pass_rate_basis_points != pass_rate_basis_points
                || result.passed != passed
            {
                return Err(format!(
                    "family {family_ref} aggregate is not reproducible from its assignments"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn turn() -> CandidateTurnRequest {
        CandidateTurnRequest {
            schema_version: AGENT_TURN_REQUEST_V1.into(),
            tenant_id: "tenant:test".into(),
            request_id: "request:test".into(),
            thread_ref: "thread:test".into(),
            context_scope_ref: None,
            actor_ref: "actor:test".into(),
            assessment_at: "2026-08-03T00:00:00Z".into(),
            message: "Can you help me make sense of this?".into(),
            history: Vec::new(),
            history_metadata: Vec::new(),
            working_state: None,
            effect_authorizations: Vec::new(),
        }
    }

    #[test]
    fn candidate_surface_has_no_private_episode_fields() {
        let spec = SupervisorEpisodeSpec {
            schema_version: SUPERVISOR_EPISODE_V1.into(),
            episode_ref: "private-episode".into(),
            private_context: PrivateEpisodeContext {
                operator_brief: serde_json::json!({"goal": "hidden"}),
                world_ref: "private-world".into(),
                world_digest: "sha256:private".into(),
            },
            initial_turn: turn(),
            limits: EpisodeLimits {
                max_exchanges: 4,
                turn_timeout_ms: 60_000,
                operator_timeout_ms: 30_000,
                lane_latency_limits_ms: BTreeMap::from([
                    ("converse".into(), 30_000),
                    ("continue".into(), 30_000),
                ]),
                restart_after_exchange: Some(1),
            },
        };
        let candidate_json = serde_json::to_string(&spec.initial_turn).unwrap();
        assert!(!candidate_json.contains("private-episode"));
        assert!(!candidate_json.contains("private-world"));
        assert!(!candidate_json.contains("hidden"));
    }

    #[test]
    fn digest_is_stable_across_object_key_order() {
        assert_eq!(
            sha256_json(&serde_json::json!({"b": 2, "a": 1})).unwrap(),
            sha256_json(&serde_json::json!({"a": 1, "b": 2})).unwrap()
        );
    }

    #[test]
    fn blind_grade_is_bound_to_the_exact_packet() {
        let packet = DigestEnvelope::new(BlindPacket {
            schema_version: BLIND_PACKET_V1.into(),
            assignment_ref: "assignment:one".into(),
            candidate_alias: "candidate:blue".into(),
            evaluation_brief: serde_json::json!({"goal": "Help the operator"}),
            transcript: Vec::new(),
            telemetry: HarnessTelemetry {
                exchange_count: 1,
                total_latency_ms: 1,
                tool_call_count: 0,
                restart_observed: false,
            },
            deterministic_defects: Vec::new(),
        })
        .unwrap();
        let mut grade = BlindGrade {
            schema_version: BLIND_GRADE_V1.into(),
            assignment_ref: packet.payload.assignment_ref.clone(),
            packet_digest: packet.payload_digest.clone(),
            grader_identity_digest: "sha256:grader".into(),
            scores: BlindScores {
                human_usefulness: 90,
                evidence_discipline: 90,
                initiative: 90,
                continuity: 90,
                burden_reduction: 90,
                bounded_authority: 90,
            },
            terminal_defect: false,
            rationale: "Useful and grounded.".into(),
        };
        assert!(grade.validate_for(&packet).is_ok());
        grade.packet_digest = "sha256:tampered".into();
        assert!(grade.validate_for(&packet).is_err());
    }

    fn v2_manifest() -> SealedEpisodeManifestV2 {
        SealedEpisodeManifestV2 {
            schema_version: SEALED_EPISODE_MANIFEST_V2.into(),
            manifest_ref: "sealed-manifest:one".into(),
            scenario_digest: "sha256:scenario".into(),
            generator: SurfaceGeneratorAttestationV2 {
                generator_ref: "surface-generator:v2".into(),
                artifact_digest: "sha256:generator".into(),
                semantic_template_digest: "sha256:template".into(),
                surface_seed_commitment: "sha256:seed-commitment".into(),
            },
            program: EpisodeEventProgramV2 {
                schema_version: EPISODE_EVENT_PROGRAM_V2.into(),
                program_ref: "program:one".into(),
                events: vec![ProgrammedEventV2::Message {
                    event_ref: "event:one".into(),
                    thread_alias: "slack-thread://t-one".into(),
                    actor_alias: "slack-user://u-one".into(),
                    message: "Can you pick this back up?".into(),
                    at: "2026-08-03T00:00:00Z".into(),
                }],
            },
            limits: EpisodeLimitsV2 {
                max_events: 8,
                max_candidate_turns: 6,
                candidate_turn_timeout_ms: 120_000,
                operator_turn_timeout_ms: 30_000,
                episode_timeout_ms: 600_000,
                phase_latency_limits_ms: BTreeMap::from([("route".into(), 20_000)]),
            },
            world_digest: "sha256:world".into(),
            operator_controller: OperatorControllerAttestationV2 {
                controller_ref: "controller:v2".into(),
                artifact_digest: "sha256:controller".into(),
                policy_digest: "sha256:policy".into(),
                principal_ref: "principal:supervisor".into(),
            },
            candidate_surface_contract_digest: "sha256:candidate-surface".into(),
        }
    }

    fn criterion(status: CriterionStatusV2) -> OperatorCriterionStateV2 {
        OperatorCriterionStateV2 {
            criterion_ref: "criterion:useful-answer".into(),
            status,
            evidence_refs: Vec::new(),
        }
    }

    #[test]
    fn sealed_manifest_digest_binds_every_material_component() {
        let original = v2_manifest();
        let digest = original.digest().unwrap();

        let mut changed = original.clone();
        changed.scenario_digest = "sha256:different-scenario".into();
        assert_ne!(digest, changed.digest().unwrap());

        let mut changed = original.clone();
        changed.generator.artifact_digest = "sha256:different-generator".into();
        assert_ne!(digest, changed.digest().unwrap());

        let mut changed = original.clone();
        changed
            .program
            .events
            .push(ProgrammedEventV2::AdvanceClock {
                event_ref: "event:two".into(),
                from: "2026-08-03T00:00:00Z".into(),
                to: "2026-08-03T01:00:00Z".into(),
            });
        assert_ne!(digest, changed.digest().unwrap());

        let mut changed = original.clone();
        changed.limits.max_candidate_turns += 1;
        assert_ne!(digest, changed.digest().unwrap());

        let mut changed = original.clone();
        changed.world_digest = "sha256:different-world".into();
        assert_ne!(digest, changed.digest().unwrap());

        let mut changed = original;
        changed.operator_controller.policy_digest = "sha256:different-policy".into();
        assert_ne!(digest, changed.digest().unwrap());
    }

    #[test]
    fn operator_conclusion_requires_all_stable_criteria_satisfied() {
        let mut receipt = OperatorDecisionReceiptV2 {
            schema_version: OPERATOR_DECISION_RECEIPT_V2.into(),
            episode_manifest_digest: "sha256:manifest".into(),
            sequence: 2,
            operator_request_digest: "sha256:request".into(),
            controller: v2_manifest().operator_controller,
            criteria_receipt_digest: "sha256:criteria".into(),
            criteria_before: vec![criterion(CriterionStatusV2::Unsatisfied)],
            disposition: OperatorDispositionV2::Conclude,
            emitted_event: None,
            criteria_after: vec![criterion(CriterionStatusV2::Unsatisfied)],
            reason_code: "candidate_claimed_completion".into(),
            decided_at: "2026-08-03T00:01:00Z".into(),
        };
        assert!(receipt.validate_semantics().is_err());

        receipt.criteria_after = vec![criterion(CriterionStatusV2::Satisfied)];
        assert!(receipt.validate_semantics().is_ok());

        receipt.disposition = OperatorDispositionV2::Continue;
        assert!(receipt.validate_semantics().is_err());
        receipt.emitted_event = Some(ProgrammedEventV2::Correction {
            event_ref: "event:correction".into(),
            thread_alias: "slack-thread://t-one".into(),
            actor_alias: "slack-user://u-one".into(),
            replaces_event_ref: "event:one".into(),
            message: "That is not what I asked you to verify.".into(),
            at: "2026-08-03T00:02:00Z".into(),
        });
        assert!(receipt.validate_semantics().is_ok());
    }

    #[test]
    fn candidate_visible_aliases_reject_evaluator_markers() {
        let mut aliases = CandidateVisibleAliasesV2 {
            tenant_id: "slack-workspace://w-one".into(),
            request_id: "slack-event://e-one".into(),
            thread_ref: "slack-thread://t-one".into(),
            actor_ref: "slack-user://u-one".into(),
            context_scope_ref: Some("slack-context-scope://s-one".into()),
            delivery_ref: "slack-delivery://d-one".into(),
        };
        assert!(aliases.validate().is_ok());
        aliases.request_id = "blackbox-request:one".into();
        assert!(aliases.validate().is_err());
    }

    #[test]
    fn suite_coverage_and_private_assignment_commitment_are_separate() {
        let suite = SealedSuiteManifestV2 {
            schema_version: SEALED_SUITE_MANIFEST_V2.into(),
            suite_ref: "suite:sealed".into(),
            corpus_digest: "sha256:corpus".into(),
            suite_generator_digest: "sha256:suite-generator".into(),
            episode_bindings: vec![SuiteEpisodeBindingV2 {
                episode_manifest_digest: v2_manifest().digest().unwrap(),
                family_ref: "family:correction".into(),
                semantic_template_ref: "template:one".into(),
                surface_variant_ref: "surface:one".into(),
                sample_index: 1,
                comparison_pair_ref: "pair:one".into(),
            }],
            family_requirements: vec![SuiteFamilyRequirementV2 {
                family_ref: "family:correction".into(),
                minimum_episode_count: 1,
                minimum_surface_variant_count: 1,
                minimum_sample_count_per_variant: 1,
            }],
            assignment_policy_digest: "sha256:assignment-policy".into(),
            promotion_policy_digest: "sha256:promotion-policy".into(),
        };
        assert!(suite.validate_coverage().is_ok());
        let sealed = SealedHoldoutAssignmentsV2 {
            schema_version: SEALED_HOLDOUT_ASSIGNMENTS_V2.into(),
            suite_manifest_digest: suite.digest().unwrap(),
            blinding_nonce: "private-nonce-with-at-least-thirty-two-bytes".into(),
            assignments: vec![PrivateHoldoutAssignmentV2 {
                assignment_ref: "private-assignment:one".into(),
                assignment_alias: "assignment:red".into(),
                episode_manifest_digest: v2_manifest().digest().unwrap(),
                candidate_attestation_digest: "sha256:private-candidate".into(),
                candidate_alias: "participant:blue".into(),
                run_index: 0,
                presentation_order: 0,
            }],
        };
        let commitment = sealed.validate_and_commit().unwrap();
        let public = serde_json::to_string(&commitment).unwrap();
        assert!(!public.contains("private-nonce"));
        assert!(!public.contains("private-assignment"));
        assert!(!public.contains("private-candidate"));
        assert_eq!(commitment.assignment_count, 1);
    }

    #[test]
    fn candidate_operator_and_grader_principals_must_be_distinct() {
        let principal = |name: &str| RuntimePrincipalAttestationV2 {
            principal_ref: format!("principal:{name}"),
            artifact_digest: format!("sha256:{name}-artifact"),
            endpoint_identity_digest: format!("sha256:{name}-endpoint"),
        };
        let mut principals = ExecutionPrincipalsV2 {
            schema_version: EXECUTION_PRINCIPALS_V2.into(),
            supervisor: principal("supervisor"),
            candidate: principal("runtime"),
            operator: principal("operator"),
            world_controller: principal("world"),
        };
        assert!(principals.validate_separation().is_ok());
        assert!(
            principals
                .validate_grader_separation("principal:grader")
                .is_ok()
        );
        assert!(
            principals
                .validate_grader_separation("principal:runtime")
                .is_err()
        );
        principals.operator.principal_ref = principals.candidate.principal_ref.clone();
        assert!(principals.validate_separation().is_err());
    }

    #[test]
    fn deterministic_criteria_receipt_binds_transition_evidence() {
        let before = vec![criterion(CriterionStatusV2::Unsatisfied)];
        let after = vec![OperatorCriterionStateV2 {
            criterion_ref: "criterion:useful-answer".into(),
            status: CriterionStatusV2::Satisfied,
            evidence_refs: vec!["observation:one".into()],
        }];
        let mut receipt = DeterministicCriteriaReceiptV2 {
            schema_version: DETERMINISTIC_CRITERIA_RECEIPT_V2.into(),
            criteria_policy_digest: "sha256:criteria-policy".into(),
            operator_request_digest: "sha256:operator-request".into(),
            definitions: vec![OperatorCriterionDefinitionV2 {
                criterion_ref: "criterion:useful-answer".into(),
                evaluation_kind: CriterionEvaluationKindV2::AuthoritativeFact,
                rule_digest: "sha256:criterion-rule".into(),
                required_evidence_count: 1,
            }],
            before_snapshot_digest: sha256_json(&before).unwrap(),
            after_snapshot_digest: sha256_json(&after).unwrap(),
            transitions: vec![CriterionTransitionV2 {
                criterion_ref: "criterion:useful-answer".into(),
                before: CriterionStatusV2::Unsatisfied,
                after: CriterionStatusV2::Satisfied,
                evidence_refs: vec!["observation:one".into()],
            }],
        };
        assert!(receipt.validate_against(&before, &after).is_ok());
        receipt.transitions[0].evidence_refs.clear();
        assert!(receipt.validate_against(&before, &after).is_err());
    }

    #[test]
    fn phase_telemetry_accounts_for_repairs_and_end_to_end_time() {
        let mut telemetry = ExchangePhaseTelemetryV2 {
            exchange_sequence: 1,
            end_to_end_ms: 15,
            accounted_phase_ms: 12,
            unaccounted_overhead_ms: 3,
            phases: vec![PhaseTimingReceiptV2 {
                exchange_sequence: 1,
                phase: ExecutionPhaseV2::Critique,
                attempt: 2,
                started_at: "2026-08-03T00:00:00Z".into(),
                completed_at: "2026-08-03T00:00:00.012Z".into(),
                duration_ms: 12,
                budget_ms: 1_000,
                input_digest: "sha256:critic-input".into(),
                output_digest: Some("sha256:critic-output".into()),
                outcome: PhaseOutcomeV2::Completed,
                model_call_count: 1,
                tool_call_count: 0,
                repair_count: 1,
            }],
        };
        assert!(telemetry.validate_accounting().is_ok());
        telemetry.unaccounted_overhead_ms = 2;
        assert!(telemetry.validate_accounting().is_err());
    }

    #[test]
    fn v2_blind_packets_omit_runtime_and_private_identity() {
        let task = BlindTaskBriefV2 {
            operator_request: "Continue the work and explain the decision.".into(),
            success_definition: "The operator can act without another handoff.".into(),
        };
        let content = ContentBlindPacketV2 {
            schema_version: CONTENT_BLIND_PACKET_V2.into(),
            assignment_alias: "assignment:red".into(),
            candidate_alias: "participant:blue".into(),
            task: task.clone(),
            transcript: vec![BlindTranscriptTurn {
                role: "assistant".into(),
                message: "I checked the bounded source and here is the decision.".into(),
            }],
        };
        let evidence = EvidenceBlindPacketV2 {
            schema_version: EVIDENCE_BLIND_PACKET_V2.into(),
            assignment_alias: "assignment:red".into(),
            candidate_alias: "participant:blue".into(),
            task,
            claims: vec![CandidateClaimV2 {
                claim_ref: "claim:one".into(),
                text: "The bounded source returned one current record.".into(),
                cited_observation_refs: vec!["observation:a".into()],
            }],
            authoritative_facts: vec![BlindAuthoritativeFactV2 {
                observation_alias: "observation:a".into(),
                subject_alias: "subject:a".into(),
                predicate: "current_record_count".into(),
                value: serde_json::json!(1),
                state: AuthoritativeEvidenceStateV2::Observed,
                complete: true,
                observed_at: "2026-08-03T00:00:30Z".into(),
            }],
            authoritative_actions: Vec::new(),
        };
        let operational = OperationalBlindPacketV2 {
            schema_version: OPERATIONAL_BLIND_PACKET_V2.into(),
            assignment_alias: "assignment:red".into(),
            candidate_alias: "participant:blue".into(),
            exchanges: vec![ExchangePhaseTelemetryV2 {
                exchange_sequence: 1,
                end_to_end_ms: 12,
                accounted_phase_ms: 10,
                unaccounted_overhead_ms: 2,
                phases: vec![PhaseTimingReceiptV2 {
                    exchange_sequence: 1,
                    phase: ExecutionPhaseV2::Route,
                    attempt: 1,
                    started_at: "2026-08-03T00:00:00Z".into(),
                    completed_at: "2026-08-03T00:00:00.010Z".into(),
                    duration_ms: 10,
                    budget_ms: 1_000,
                    input_digest: "sha256:route-input".into(),
                    output_digest: Some("sha256:route-output".into()),
                    outcome: PhaseOutcomeV2::Completed,
                    model_call_count: 1,
                    tool_call_count: 0,
                    repair_count: 0,
                }],
            }],
            deterministic_defects: Vec::new(),
            burden: InteractionBurdenReceiptV2 {
                operator_message_count: 1,
                clarification_request_count: 0,
                repeated_read_count: 0,
                model_call_count: 1,
                tool_call_count: 0,
                repair_loop_count: 0,
                retry_count: 0,
                unresolved_handoff_count: 0,
            },
            restart_count: 1,
            delivered_exchange_count: 1,
        };
        let encoded = format!(
            "{}{}{}",
            serde_json::to_string(&content).unwrap(),
            serde_json::to_string(&evidence).unwrap(),
            serde_json::to_string(&operational).unwrap()
        );
        for private_value in [
            "global.anthropic.claude-opus",
            "amazon-bedrock",
            "0123456789abcdef0123456789abcdef01234567",
            "principal:supervisor",
            "sha256:policy",
            "sealed-manifest:one",
        ] {
            assert!(!encoded.contains(private_value));
        }
        assert!(
            !serde_json::to_string(&content)
                .unwrap()
                .contains("duration_ms")
        );
    }

    #[test]
    fn independent_grade_resolves_citations_in_the_exact_materialized_packet() {
        let packet = MaterializedBlindPacketV2::Content(ContentBlindPacketV2 {
            schema_version: CONTENT_BLIND_PACKET_V2.into(),
            assignment_alias: "assignment:red".into(),
            candidate_alias: "participant:blue".into(),
            task: BlindTaskBriefV2 {
                operator_request: "Explain the decision.".into(),
                success_definition: "The operator can act.".into(),
            },
            transcript: vec![BlindTranscriptTurn {
                role: "assistant".into(),
                message: "I checked the source and here is the decision.".into(),
            }],
        });
        let mut grade = IndependentGradeReceiptV2 {
            schema_version: INDEPENDENT_GRADE_RECEIPT_V2.into(),
            grade_ref: "grade:one".into(),
            suite_manifest_digest: "sha256:suite".into(),
            assignment_alias: "assignment:red".into(),
            packet_kind: BlindPacketKindV2::Content,
            packet_digest: packet.payload_digest().unwrap(),
            grader: GraderAttestationV2 {
                principal_ref: "principal:grader".into(),
                artifact_digest: "sha256:grader".into(),
                rubric_digest: "sha256:rubric".into(),
                calibration_receipt_digest: "sha256:calibration".into(),
                calibration_passed: true,
            },
            scores: vec![DimensionScoreV2 {
                dimension: GradeDimensionV2::HumanUsefulness,
                score: 90,
            }],
            hard_defect_codes: Vec::new(),
            citations: vec![GradeCitationV2 {
                dimension: GradeDimensionV2::HumanUsefulness,
                packet_item_ref: "/transcript/0/message".into(),
                rationale: "The response gives the operator a decision.".into(),
            }],
            graded_at: "2026-08-03T00:01:00Z".into(),
        };

        assert!(packet.validate_grade_binding(&grade).is_ok());
        grade.packet_digest = "sha256:substituted".into();
        assert_eq!(
            packet.validate_grade_binding(&grade).unwrap_err(),
            "independent grade does not bind the exact materialized packet"
        );
        grade.packet_digest = packet.payload_digest().unwrap();
        grade.citations[0].packet_item_ref = "/transcript/9/message".into();
        assert_eq!(
            packet.validate_grade_binding(&grade).unwrap_err(),
            "independent grade citation does not resolve in the bound materialized packet"
        );
    }

    #[test]
    fn supervisor_execution_is_ineligible_before_independent_grades() {
        let receipt = SupervisorExecutionReceiptV2 {
            schema_version: SUPERVISOR_EXECUTION_RECEIPT_V2.into(),
            episode_manifest_digest: v2_manifest().digest().unwrap(),
            candidate_attestation_digest: "sha256:attestation".into(),
            operator_decisions: Vec::new(),
            fact_receipt_digests: Vec::new(),
            action_receipt_digests: Vec::new(),
            transcript_digest: "sha256:transcript".into(),
            deterministic_defects: Vec::new(),
            promotion_disposition:
                ExecutionPromotionDispositionV2::IneligiblePendingIndependentGrades,
            completed_at: "2026-08-03T00:03:00Z".into(),
        };
        let envelope = SignedReceiptEnvelopeV2 {
            schema_version: SIGNED_RECEIPT_ENVELOPE_V2.into(),
            payload_digest: SignedReceiptEnvelopeV2::signing_payload_digest(&receipt).unwrap(),
            payload: receipt,
            signer: SignerAttestationV2 {
                principal_ref: "principal:supervisor".into(),
                algorithm: SignatureAlgorithmV2::AwsKmsEcdsaSha256,
                key_ref: "kms-key:supervisor".into(),
            },
            signature_base64: "c2lnbmF0dXJl".into(),
        };
        assert!(envelope.validate_digest_and_signature_shape().is_ok());
    }
}
