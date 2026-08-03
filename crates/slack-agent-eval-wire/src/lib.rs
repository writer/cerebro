#![deny(unsafe_code)]

//! Provider-neutral wire contracts for black-box Slack agent evaluation.
//!
//! This crate deliberately contains no model client, holdout content, credentials,
//! runtime adapter, or environment route. Candidate and evaluator processes can
//! share protocol records without sharing private evaluation state.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const AGENT_TURN_REQUEST_V1: &str = "agent-turn-request/v1";
pub const AGENT_DELIVERY_RECEIPT_V1: &str = "agent-delivery-receipt/v1";
pub const SUPERVISOR_EPISODE_V1: &str = "slack-agent-supervisor-episode/v1";
pub const OPERATOR_TURN_V1: &str = "slack-agent-operator-turn/v1";
pub const BLACKBOX_RECEIPT_V1: &str = "slack-agent-blackbox-receipt/v1";
pub const BLIND_PACKET_V1: &str = "slack-agent-blind-packet/v1";
pub const BLIND_GRADE_V1: &str = "slack-agent-blind-grade/v1";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateTurnRequest {
    pub schema_version: String,
    pub tenant_id: String,
    pub request_id: String,
    pub thread_ref: String,
    #[serde(default)]
    pub context_scope_ref: Option<String>,
    pub actor_ref: String,
    pub assessment_at: String,
    pub message: String,
    #[serde(default)]
    pub history: Vec<ConversationMessage>,
    #[serde(default)]
    pub history_metadata: Vec<ConversationMessageMetadata>,
    pub working_state: Option<Value>,
    #[serde(default)]
    pub effect_authorizations: Vec<EffectAuthorization>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessage {
    pub role: String,
    pub content: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessageMetadata {
    #[serde(default)]
    pub actor_ref: Option<String>,
    #[serde(default)]
    pub message_ref: Option<String>,
    #[serde(default)]
    pub received_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectAuthorization {
    pub approval_ref: String,
    pub tenant_id: String,
    pub request_id: String,
    pub thread_ref: String,
    pub actor_ref: String,
    pub tool_id: String,
    pub input_digest: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CandidateTurnOutcome {
    PendingDelivery {
        schema_version: String,
        lane: String,
        markdown: String,
        final_state: String,
        evidence_refs: Vec<String>,
        tool_call_count: usize,
        working_state: Option<Value>,
    },
    Delivered {
        schema_version: String,
        lane: String,
        markdown: String,
        final_state: String,
        evidence_refs: Vec<String>,
        tool_call_count: usize,
        working_state: Option<Value>,
    },
    ApprovalRequired {
        schema_version: String,
        lane: String,
        request: Value,
        tool_call_count: usize,
    },
    Ignored {
        schema_version: String,
    },
}

impl CandidateTurnOutcome {
    #[must_use]
    pub fn markdown(&self) -> Option<&str> {
        match self {
            Self::PendingDelivery { markdown, .. } | Self::Delivered { markdown, .. } => {
                Some(markdown)
            }
            Self::ApprovalRequired { .. } | Self::Ignored { .. } => None,
        }
    }

    #[must_use]
    pub const fn needs_delivery(&self) -> bool {
        matches!(self, Self::PendingDelivery { .. })
    }

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
pub struct CandidateDeliveryReceipt {
    pub schema_version: String,
    pub tenant_id: String,
    pub thread_ref: String,
    pub request_id: String,
    pub transport: String,
    pub delivery_ref: String,
    pub payload_digest: String,
    pub delivered_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeLimits {
    pub max_exchanges: usize,
    pub turn_timeout_ms: u64,
    pub operator_timeout_ms: u64,
    pub lane_latency_limits_ms: BTreeMap<String, u64>,
    #[serde(default)]
    pub restart_after_exchange: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateEpisodeContext {
    pub operator_brief: Value,
    pub world_ref: String,
    pub world_digest: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorEpisodeSpec {
    pub schema_version: String,
    pub episode_ref: String,
    pub private_context: PrivateEpisodeContext,
    pub initial_turn: CandidateTurnRequest,
    pub limits: EpisodeLimits,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptTurn {
    pub role: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRuntimeAttestation {
    pub schema_version: String,
    pub agent_ready: bool,
    pub build_commit_sha: String,
    pub build_tree_clean: bool,
    pub runtime_instance_ref: String,
    pub model_provider: Option<String>,
    pub model_id: Option<String>,
    pub model_config_sha256: Option<String>,
    pub session_schema_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateAttestation {
    pub candidate_ref: String,
    pub artifact_digest: String,
    pub runtime: CandidateRuntimeAttestation,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeReceipt {
    pub sequence: usize,
    pub request_digest: String,
    pub response_digest: String,
    pub runtime_instance_ref: String,
    pub started_at: String,
    pub completed_at: String,
    pub latency_ms: u64,
    pub request: CandidateTurnRequest,
    pub outcome: CandidateTurnOutcome,
    pub delivery: Option<CandidateDeliveryReceipt>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorTurnRequest {
    pub schema_version: String,
    pub episode_ref: String,
    pub private_context: PrivateEpisodeContext,
    pub transcript: Vec<TranscriptTurn>,
    pub latest_exchange: ExchangeReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperatorDecision {
    Continue { message: String, reason: String },
    Conclude { reason: String },
    Abort { reason: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicDefect {
    pub code: String,
    pub detail: String,
    pub terminal: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessTelemetry {
    pub exchange_count: usize,
    pub total_latency_ms: u64,
    pub tool_call_count: usize,
    pub restart_observed: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlackboxReceipt {
    pub schema_version: String,
    pub episode_ref: String,
    pub candidate: CandidateAttestation,
    pub private_context_digest: String,
    pub transcript: Vec<TranscriptTurn>,
    pub exchanges: Vec<ExchangeReceipt>,
    pub telemetry: HarnessTelemetry,
    pub deterministic_defects: Vec<DeterministicDefect>,
    pub completed_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DigestEnvelope<T> {
    pub payload: T,
    pub payload_digest: String,
}

impl<T: Serialize> DigestEnvelope<T> {
    pub fn new(payload: T) -> Result<Self, serde_json::Error> {
        let payload_digest = sha256_json(&payload)?;
        Ok(Self {
            payload,
            payload_digest,
        })
    }

    pub fn verify_digest(&self) -> Result<bool, serde_json::Error> {
        Ok(self.payload_digest == sha256_json(&self.payload)?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindTranscriptTurn {
    pub role: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindPacket {
    pub schema_version: String,
    pub assignment_ref: String,
    pub candidate_alias: String,
    pub evaluation_brief: Value,
    pub transcript: Vec<BlindTranscriptTurn>,
    pub telemetry: HarnessTelemetry,
    pub deterministic_defects: Vec<DeterministicDefect>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindGrade {
    pub schema_version: String,
    pub assignment_ref: String,
    pub packet_digest: String,
    pub grader_identity_digest: String,
    pub scores: BlindScores,
    pub terminal_defect: bool,
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindScores {
    pub human_usefulness: u8,
    pub evidence_discipline: u8,
    pub initiative: u8,
    pub continuity: u8,
    pub burden_reduction: u8,
    pub bounded_authority: u8,
}

impl BlindGrade {
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

pub fn sha256_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    let bytes = serde_json::to_vec(&canonicalize(value))?;
    Ok(sha256_bytes(&bytes))
}

#[must_use]
pub fn sha256_text(value: &str) -> String {
    sha256_bytes(value.as_bytes())
}

fn sha256_bytes(value: &[u8]) -> String {
    let digest = Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{digest}")
}

fn canonicalize(value: Value) -> Value {
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
}
