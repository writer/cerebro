//! Fail-closed execution supervisor for sealed V2 Slack-agent episodes.
//!
//! The supervisor owns private manifest sequencing. Candidate-facing transport
//! requests contain only normal Slack-shaped aliases and the programmed event's
//! visible content. World, lifecycle, and operator controllers are trusted
//! endpoints and receive the private bindings needed to produce signed receipts.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    time::Duration,
};

use cerebro_slack_agent_eval_wire::{
    ASSIGNMENT_EXECUTION_BINDING_V2, AUTHORITATIVE_ACTION_RECEIPT_V2,
    AUTHORITATIVE_FACT_RECEIPT_V2, AssignmentExecutionBindingV2, AuthoritativeActionReceiptV2,
    AuthoritativeEvidenceStateV2, AuthoritativeFactReceiptV2, CandidateVisibleAliasesV2,
    CriterionStatusV2, DeterministicCriteriaReceiptV2, DeterministicDefect,
    ExchangePhaseTelemetryV2, ExecutionPhaseV2, ExecutionPrincipalsV2,
    ExecutionPromotionDispositionV2, OperatorCriterionStateV2, OperatorDecisionReceiptV2,
    OperatorDispositionV2, PhaseOutcomeV2, ProgrammedEventV2, SEALED_EPISODE_MANIFEST_V2,
    SIGNED_RECEIPT_ENVELOPE_V2, SUPERVISOR_EXECUTION_RECEIPT_V2, SealedEpisodeManifestV2,
    SignedReceiptEnvelopeV2, SignerAttestationV2, SupervisorExecutionReceiptV2, TranscriptTurn,
    sha256_json,
};
use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const TRANSPORT_DISPATCH_V2: &str = "slack-agent-transport-dispatch/v2";
const TRUSTED_CONTROL_EVENT_V2: &str = "slack-agent-trusted-control-event/v2";
const TRUSTED_EVENT_RECEIPT_V2: &str = "slack-agent-trusted-event-receipt/v2";
const OPERATOR_EVALUATION_REQUEST_V2: &str = "slack-agent-operator-evaluation-request/v2";
const OPERATOR_EVALUATION_RECEIPT_V2: &str = "slack-agent-operator-evaluation-receipt/v2";
const MAX_ERROR_CHARS: usize = 512;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedEndpointBindingV2 {
    pub url: String,
    pub principal_ref: String,
    pub endpoint_identity_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedExecutionEndpointsV2 {
    pub transport: TrustedEndpointBindingV2,
    pub world: TrustedEndpointBindingV2,
    pub lifecycle: TrustedEndpointBindingV2,
    pub operator: TrustedEndpointBindingV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateEventAliasBindingV2 {
    /// Private supervisor key. This value is never serialized into a transport
    /// dispatch.
    pub event_ref: String,
    pub aliases: CandidateVisibleAliasesV2,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorExecutionConfigV2 {
    pub manifest: SealedEpisodeManifestV2,
    pub candidate_attestation_digest: String,
    pub assignment: SupervisorAssignmentContextV2,
    pub principals: ExecutionPrincipalsV2,
    pub endpoints: TrustedExecutionEndpointsV2,
    pub candidate_aliases: Vec<CandidateEventAliasBindingV2>,
    pub initial_criteria: Vec<OperatorCriterionStateV2>,
}

/// Private assignment metadata supplied by the sealed supervisor. Promotion
/// re-validates these fields against the committed private assignment manifest
/// and suite before accepting the resulting signed binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorAssignmentContextV2 {
    pub holdout_assignment_commitment_digest: String,
    pub assignment_alias: String,
    pub comparison_pair_ref: String,
    pub sample_index: usize,
    pub run_index: usize,
    pub presentation_order: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedEndpointKindV2 {
    Transport,
    World,
    Lifecycle,
    Operator,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPhaseTelemetryV2 {
    pub endpoint: TrustedEndpointKindV2,
    pub telemetry: ExchangePhaseTelemetryV2,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorExecutionOutputV2 {
    pub receipt: SupervisorExecutionReceiptV2,
    pub assignment_execution_binding: AssignmentExecutionBindingV2,
    pub phase_telemetry: Vec<EndpointPhaseTelemetryV2>,
    pub fact_receipts: Vec<SignedReceiptEnvelopeV2<AuthoritativeFactReceiptV2>>,
    pub action_receipts: Vec<SignedReceiptEnvelopeV2<AuthoritativeActionReceiptV2>>,
    pub transcript: Vec<TranscriptTurn>,
}

impl SupervisorExecutionOutputV2 {
    #[must_use]
    pub fn passed_deterministic_execution(&self) -> bool {
        !self
            .receipt
            .deterministic_defects
            .iter()
            .any(|defect| defect.terminal)
    }
}

/// Cryptographic verification is deliberately a port rather than a boolean.
/// Shape validation is always performed before this method is called.
pub trait ReceiptSignatureVerifierV2: Send + Sync {
    fn verify(
        &self,
        payload_digest: &str,
        signer: &SignerAttestationV2,
        signature_base64: &str,
    ) -> Result<(), String>;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum CandidateSurfaceEventV2 {
    Message {
        aliases: CandidateVisibleAliasesV2,
        message: String,
        at: String,
    },
    Correction {
        aliases: CandidateVisibleAliasesV2,
        replaces_request_id: String,
        message: String,
        at: String,
    },
    OpenThread {
        aliases: CandidateVisibleAliasesV2,
        message: String,
        at: String,
    },
    Wake {
        aliases: CandidateVisibleAliasesV2,
        commitment_ref: String,
        occurrence_ref: String,
        at: String,
    },
    Authorize {
        aliases: CandidateVisibleAliasesV2,
        approval_ref: String,
        tool_id: String,
        input_digest: String,
        at: String,
    },
}

impl CandidateSurfaceEventV2 {
    fn aliases(&self) -> &CandidateVisibleAliasesV2 {
        match self {
            Self::Message { aliases, .. }
            | Self::Correction { aliases, .. }
            | Self::OpenThread { aliases, .. }
            | Self::Wake { aliases, .. }
            | Self::Authorize { aliases, .. } => aliases,
        }
    }

    fn operator_turn(&self) -> Option<TranscriptTurn> {
        match self {
            Self::Message { message, .. }
            | Self::Correction { message, .. }
            | Self::OpenThread { message, .. } => Some(TranscriptTurn {
                role: "operator".into(),
                message: message.clone(),
            }),
            Self::Wake { .. } | Self::Authorize { .. } => None,
        }
    }

    fn validate(&self) -> Result<(), String> {
        self.aliases().validate()?;
        match self {
            Self::Message { message, at, .. } | Self::OpenThread { message, at, .. } => {
                require_visible_text(message, "candidate message")?;
                parse_time(at, "candidate event time")?;
            }
            Self::Correction {
                replaces_request_id,
                message,
                at,
                ..
            } => {
                require_candidate_alias(replaces_request_id, "replaced request")?;
                require_visible_text(message, "candidate correction")?;
                parse_time(at, "candidate event time")?;
            }
            Self::Wake {
                commitment_ref,
                occurrence_ref,
                at,
                ..
            } => {
                require_candidate_alias(commitment_ref, "commitment")?;
                require_candidate_alias(occurrence_ref, "occurrence")?;
                parse_time(at, "candidate event time")?;
            }
            Self::Authorize {
                approval_ref,
                tool_id,
                input_digest,
                at,
                ..
            } => {
                require_candidate_alias(approval_ref, "approval")?;
                require_candidate_alias(tool_id, "tool")?;
                require_sha256(input_digest, "authorization input")?;
                parse_time(at, "candidate event time")?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateTransportDispatchV2 {
    pub schema_version: String,
    /// This is the complete candidate-visible payload. The sealed manifest,
    /// event ref, scenario digest, program ref, and criteria are absent.
    pub candidate_event: CandidateSurfaceEventV2,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedControlEventRequestV2 {
    pub schema_version: String,
    pub episode_manifest_digest: String,
    pub sequence: usize,
    pub event: ProgrammedEventV2,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedEventReceiptV2 {
    pub schema_version: String,
    pub sequence: usize,
    pub request_digest: String,
    pub transcript_delta: Vec<TranscriptTurn>,
    pub telemetry: ExchangePhaseTelemetryV2,
    pub fact_receipts: Vec<SignedReceiptEnvelopeV2<AuthoritativeFactReceiptV2>>,
    pub action_receipts: Vec<SignedReceiptEnvelopeV2<AuthoritativeActionReceiptV2>>,
    pub deterministic_defects: Vec<DeterministicDefect>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorEvaluationRequestV2 {
    pub schema_version: String,
    pub episode_manifest_digest: String,
    pub sequence: usize,
    pub expected_next_event: Option<ProgrammedEventV2>,
    pub transcript_digest: String,
    pub fact_receipt_digests: Vec<String>,
    pub action_receipt_digests: Vec<String>,
    pub criteria_before: Vec<OperatorCriterionStateV2>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorEvaluationReceiptV2 {
    pub schema_version: String,
    pub decision: OperatorDecisionReceiptV2,
    pub criteria: DeterministicCriteriaReceiptV2,
    pub telemetry: ExchangePhaseTelemetryV2,
}

#[derive(Debug)]
pub struct SupervisorConfigurationErrorV2(String);

impl fmt::Display for SupervisorConfigurationErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for SupervisorConfigurationErrorV2 {}

struct ValidatedConfigV2<'a> {
    config: &'a SupervisorExecutionConfigV2,
    manifest_digest: String,
    aliases: BTreeMap<&'a str, &'a CandidateVisibleAliasesV2>,
}

struct SealedProgramCursorV2<'a> {
    events: &'a [ProgrammedEventV2],
    next_index: usize,
}

impl<'a> SealedProgramCursorV2<'a> {
    fn new(events: &'a [ProgrammedEventV2]) -> Result<Self, String> {
        if events.is_empty() {
            return Err("sealed event program contains no events".into());
        }
        Ok(Self {
            events,
            next_index: 0,
        })
    }

    fn next(&self) -> Option<&'a ProgrammedEventV2> {
        self.events.get(self.next_index)
    }

    fn accept(&mut self, emitted: &ProgrammedEventV2) -> Result<(), String> {
        let expected = self
            .next()
            .ok_or_else(|| "operator emitted an event after the sealed program ended".to_owned())?;
        if emitted != expected {
            return Err(format!(
                "operator deviated from sealed event {}",
                event_ref(expected)
            ));
        }
        self.next_index += 1;
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.next_index == self.events.len()
    }
}

/// Execute one sealed V2 episode. The receipt is always promotion-ineligible;
/// independent grades and aggregation occur in a separate authority domain.
pub async fn execute_supervisor_v2(
    config: &SupervisorExecutionConfigV2,
    verifier: &dyn ReceiptSignatureVerifierV2,
) -> Result<SupervisorExecutionOutputV2, SupervisorConfigurationErrorV2> {
    let validated = validate_config(config).map_err(SupervisorConfigurationErrorV2)?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| SupervisorConfigurationErrorV2(error.to_string()))?;
    let started = tokio::time::Instant::now();
    let mut cursor = SealedProgramCursorV2::new(&config.manifest.program.events)
        .map_err(SupervisorConfigurationErrorV2)?;
    let mut criteria = config.initial_criteria.clone();
    let mut criteria_definitions_digest = None;
    let mut transcript = Vec::new();
    let mut decisions = Vec::new();
    let mut telemetry = Vec::new();
    let mut facts = Vec::new();
    let mut actions = Vec::new();
    let mut defects = Vec::new();
    let mut completed_event_count = 0_usize;

    while let Some(event) = cursor.next().cloned() {
        if episode_timed_out(started, config.manifest.limits.episode_timeout_ms) {
            defects.push(terminal(
                "episode_timeout",
                "The sealed episode exceeded its end-to-end timeout before the next event.",
            ));
            break;
        }
        let sequence = cursor.next_index + 1;
        let operator = match operator_decision(
            &client,
            &validated,
            verifier,
            sequence,
            Some(event.clone()),
            OperatorDecisionInputsV2 {
                transcript: &transcript,
                facts: &facts,
                actions: &actions,
                criteria_before: &criteria,
                criteria_definitions_digest: &mut criteria_definitions_digest,
            },
        )
        .await
        {
            Ok(operator) => operator,
            Err(error) => {
                defects.push(terminal("operator_deviation", error));
                break;
            }
        };
        telemetry.push(EndpointPhaseTelemetryV2 {
            endpoint: TrustedEndpointKindV2::Operator,
            telemetry: operator.payload.telemetry.clone(),
        });
        criteria = operator.payload.decision.criteria_after.clone();
        let decision = operator.payload.decision;
        let Some(emitted) = decision.emitted_event.as_ref() else {
            defects.push(terminal(
                "operator_event_missing",
                "The operator did not emit the next sealed event.",
            ));
            decisions.push(decision);
            break;
        };
        if let Err(error) = cursor.accept(emitted) {
            defects.push(terminal("operator_event_mismatch", error));
            decisions.push(decision);
            break;
        }
        decisions.push(decision);

        let event_result =
            match execute_event(&client, &validated, verifier, sequence, &event).await {
                Ok(result) => result,
                Err(error) => {
                    defects.push(terminal("event_execution_failed", error));
                    break;
                }
            };
        telemetry.push(EndpointPhaseTelemetryV2 {
            endpoint: event_result.endpoint,
            telemetry: event_result.receipt.payload.telemetry.clone(),
        });
        if let Some(operator_turn) = event_result.operator_turn {
            transcript.push(operator_turn);
        }
        transcript.extend(event_result.receipt.payload.transcript_delta.clone());
        defects.extend(event_result.receipt.payload.deterministic_defects.clone());
        if let Err(error) = collect_authoritative_receipts(
            &validated,
            verifier,
            &event_result.receipt.payload.fact_receipts,
            &event_result.receipt.payload.action_receipts,
            &mut facts,
            &mut actions,
        ) {
            defects.push(terminal("authoritative_receipt_invalid", error));
        }
        completed_event_count += 1;
        if defects.iter().any(|defect| defect.terminal) {
            break;
        }
    }

    if !defects.iter().any(|defect| defect.terminal) {
        if !cursor.is_complete() {
            defects.push(terminal(
                "program_incomplete",
                "The supervisor stopped before every sealed event was executed.",
            ));
        } else {
            let final_sequence = config.manifest.program.events.len() + 1;
            match operator_decision(
                &client,
                &validated,
                verifier,
                final_sequence,
                None,
                OperatorDecisionInputsV2 {
                    transcript: &transcript,
                    facts: &facts,
                    actions: &actions,
                    criteria_before: &criteria,
                    criteria_definitions_digest: &mut criteria_definitions_digest,
                },
            )
            .await
            {
                Ok(operator) => {
                    telemetry.push(EndpointPhaseTelemetryV2 {
                        endpoint: TrustedEndpointKindV2::Operator,
                        telemetry: operator.payload.telemetry.clone(),
                    });
                    criteria = operator.payload.decision.criteria_after.clone();
                    decisions.push(operator.payload.decision);
                }
                Err(error) => defects.push(terminal("operator_conclusion_invalid", error)),
            }
        }
    }

    validate_final_accounting(
        config,
        FinalAccountingV2 {
            completed_event_count,
            decisions: &decisions,
            criteria: &criteria,
            telemetry: &telemetry,
            facts: &facts,
            actions: &actions,
        },
        &mut defects,
    );
    match crate::transcript_quality::execution_defects(&transcript) {
        Ok(transcript_defects) => defects.extend(transcript_defects),
        Err(error) => defects.push(terminal(
            "transcript_lint_failed",
            format!("The deterministic transcript lint could not bind its input: {error}"),
        )),
    }
    let fact_receipt_digests = facts
        .iter()
        .map(|receipt| receipt.payload_digest.clone())
        .collect::<Vec<_>>();
    let action_receipt_digests = actions
        .iter()
        .map(|receipt| receipt.payload_digest.clone())
        .collect::<Vec<_>>();
    let transcript_digest = sha256_json(&transcript)
        .map_err(|error| SupervisorConfigurationErrorV2(error.to_string()))?;
    let receipt = SupervisorExecutionReceiptV2 {
        schema_version: SUPERVISOR_EXECUTION_RECEIPT_V2.into(),
        episode_manifest_digest: validated.manifest_digest,
        candidate_attestation_digest: config.candidate_attestation_digest.clone(),
        operator_decisions: decisions,
        fact_receipt_digests,
        action_receipt_digests,
        transcript_digest,
        deterministic_defects: defects,
        promotion_disposition: ExecutionPromotionDispositionV2::IneligiblePendingIndependentGrades,
        completed_at: now().map_err(SupervisorConfigurationErrorV2)?,
    };
    let assignment_execution_binding = AssignmentExecutionBindingV2 {
        schema_version: ASSIGNMENT_EXECUTION_BINDING_V2.into(),
        holdout_assignment_commitment_digest: config
            .assignment
            .holdout_assignment_commitment_digest
            .clone(),
        assignment_alias: config.assignment.assignment_alias.clone(),
        episode_manifest_digest: receipt.episode_manifest_digest.clone(),
        candidate_attestation_digest: receipt.candidate_attestation_digest.clone(),
        execution_receipt_digest: sha256_json(&receipt)
            .map_err(|error| SupervisorConfigurationErrorV2(error.to_string()))?,
        comparison_pair_ref: config.assignment.comparison_pair_ref.clone(),
        sample_index: config.assignment.sample_index,
        run_index: config.assignment.run_index,
        presentation_order: config.assignment.presentation_order,
    };
    Ok(SupervisorExecutionOutputV2 {
        receipt,
        assignment_execution_binding,
        phase_telemetry: telemetry,
        fact_receipts: facts,
        action_receipts: actions,
        transcript,
    })
}

struct ExecutedEventV2 {
    endpoint: TrustedEndpointKindV2,
    receipt: SignedReceiptEnvelopeV2<TrustedEventReceiptV2>,
    operator_turn: Option<TranscriptTurn>,
}

async fn execute_event(
    client: &Client,
    config: &ValidatedConfigV2<'_>,
    verifier: &dyn ReceiptSignatureVerifierV2,
    sequence: usize,
    event: &ProgrammedEventV2,
) -> Result<ExecutedEventV2, String> {
    match event {
        ProgrammedEventV2::ChangeWorld { .. } | ProgrammedEventV2::AdvanceClock { .. } => {
            let request = TrustedControlEventRequestV2 {
                schema_version: TRUSTED_CONTROL_EVENT_V2.into(),
                episode_manifest_digest: config.manifest_digest.clone(),
                sequence,
                event: event.clone(),
            };
            let receipt = call_signed_endpoint(
                client,
                &config.config.endpoints.world,
                &request,
                config.config.manifest.limits.candidate_turn_timeout_ms,
            )
            .await?;
            validate_event_receipt(
                config,
                verifier,
                sequence,
                &request,
                TrustedEndpointKindV2::World,
                &receipt,
            )?;
            Ok(ExecutedEventV2 {
                endpoint: TrustedEndpointKindV2::World,
                receipt,
                operator_turn: None,
            })
        }
        ProgrammedEventV2::Restart { .. } => {
            let request = TrustedControlEventRequestV2 {
                schema_version: TRUSTED_CONTROL_EVENT_V2.into(),
                episode_manifest_digest: config.manifest_digest.clone(),
                sequence,
                event: event.clone(),
            };
            let receipt = call_signed_endpoint(
                client,
                &config.config.endpoints.lifecycle,
                &request,
                config.config.manifest.limits.candidate_turn_timeout_ms,
            )
            .await?;
            validate_event_receipt(
                config,
                verifier,
                sequence,
                &request,
                TrustedEndpointKindV2::Lifecycle,
                &receipt,
            )?;
            Ok(ExecutedEventV2 {
                endpoint: TrustedEndpointKindV2::Lifecycle,
                receipt,
                operator_turn: None,
            })
        }
        _ => {
            let projected = candidate_surface_event(event, &config.aliases)?;
            projected.validate()?;
            let operator_turn = projected.operator_turn();
            let request = CandidateTransportDispatchV2 {
                schema_version: TRANSPORT_DISPATCH_V2.into(),
                candidate_event: projected,
            };
            ensure_candidate_surface_is_private(&request)?;
            let receipt = call_signed_endpoint(
                client,
                &config.config.endpoints.transport,
                &request,
                config.config.manifest.limits.candidate_turn_timeout_ms,
            )
            .await?;
            validate_event_receipt(
                config,
                verifier,
                sequence,
                &request,
                TrustedEndpointKindV2::Transport,
                &receipt,
            )?;
            if receipt
                .payload
                .transcript_delta
                .iter()
                .any(|turn| turn.role != "assistant" || turn.message.trim().is_empty())
            {
                return Err(
                    "transport transcript delta must contain only non-empty assistant turns".into(),
                );
            }
            Ok(ExecutedEventV2 {
                endpoint: TrustedEndpointKindV2::Transport,
                receipt,
                operator_turn,
            })
        }
    }
}

struct OperatorDecisionInputsV2<'a> {
    transcript: &'a [TranscriptTurn],
    facts: &'a [SignedReceiptEnvelopeV2<AuthoritativeFactReceiptV2>],
    actions: &'a [SignedReceiptEnvelopeV2<AuthoritativeActionReceiptV2>],
    criteria_before: &'a [OperatorCriterionStateV2],
    criteria_definitions_digest: &'a mut Option<String>,
}

async fn operator_decision(
    client: &Client,
    config: &ValidatedConfigV2<'_>,
    verifier: &dyn ReceiptSignatureVerifierV2,
    sequence: usize,
    expected_next_event: Option<ProgrammedEventV2>,
    inputs: OperatorDecisionInputsV2<'_>,
) -> Result<SignedReceiptEnvelopeV2<OperatorEvaluationReceiptV2>, String> {
    let request = OperatorEvaluationRequestV2 {
        schema_version: OPERATOR_EVALUATION_REQUEST_V2.into(),
        episode_manifest_digest: config.manifest_digest.clone(),
        sequence,
        expected_next_event: expected_next_event.clone(),
        transcript_digest: sha256_json(&inputs.transcript).map_err(|error| error.to_string())?,
        fact_receipt_digests: inputs
            .facts
            .iter()
            .map(|receipt| receipt.payload_digest.clone())
            .collect(),
        action_receipt_digests: inputs
            .actions
            .iter()
            .map(|receipt| receipt.payload_digest.clone())
            .collect(),
        criteria_before: inputs.criteria_before.to_vec(),
    };
    let request_digest = sha256_json(&request).map_err(|error| error.to_string())?;
    let receipt: SignedReceiptEnvelopeV2<OperatorEvaluationReceiptV2> = call_signed_endpoint(
        client,
        &config.config.endpoints.operator,
        &request,
        config.config.manifest.limits.operator_turn_timeout_ms,
    )
    .await?;
    validate_signed_envelope(
        &receipt,
        &config.config.principals.operator.principal_ref,
        verifier,
    )?;
    if receipt.payload.schema_version != OPERATOR_EVALUATION_RECEIPT_V2 {
        return Err("unsupported operator endpoint receipt schema".into());
    }
    validate_phase_telemetry(
        &config.config.manifest,
        sequence,
        &receipt.payload.telemetry,
    )?;
    if receipt
        .payload
        .telemetry
        .phases
        .iter()
        .any(|phase| phase.phase != ExecutionPhaseV2::Operator)
    {
        return Err("operator endpoint emitted non-operator phase telemetry".into());
    }
    let decision = &receipt.payload.decision;
    let criteria = &receipt.payload.criteria;
    if decision.episode_manifest_digest != config.manifest_digest
        || decision.sequence != sequence
        || decision.operator_request_digest != request_digest
        || decision.controller != config.config.manifest.operator_controller
        || decision.criteria_before != inputs.criteria_before
        || criteria.operator_request_digest != request_digest
        || criteria.criteria_policy_digest
            != config.config.manifest.operator_controller.policy_digest
        || decision.criteria_receipt_digest
            != sha256_json(criteria).map_err(|error| error.to_string())?
    {
        return Err(
            "operator decision is not bound to this request, controller, or criteria".into(),
        );
    }
    criteria.validate_against(inputs.criteria_before, &decision.criteria_after)?;
    decision.validate_semantics()?;
    let definitions_digest =
        sha256_json(&criteria.definitions).map_err(|error| error.to_string())?;
    match inputs.criteria_definitions_digest {
        Some(expected) if expected != &definitions_digest => {
            return Err("operator criteria definitions changed during the episode".into());
        }
        Some(_) => {}
        None => *inputs.criteria_definitions_digest = Some(definitions_digest),
    }
    match (
        &expected_next_event,
        decision.disposition,
        &decision.emitted_event,
    ) {
        (Some(expected), OperatorDispositionV2::Continue, Some(actual)) if expected == actual => {}
        (Some(_), _, _) => {
            return Err("operator did not continue with the exact next sealed event".into());
        }
        (None, OperatorDispositionV2::Conclude, None) => {}
        (None, _, _) => {
            return Err("operator did not conclude after the sealed event program".into());
        }
    }
    Ok(receipt)
}

fn validate_event_receipt<T: Serialize>(
    config: &ValidatedConfigV2<'_>,
    verifier: &dyn ReceiptSignatureVerifierV2,
    sequence: usize,
    request: &T,
    endpoint: TrustedEndpointKindV2,
    receipt: &SignedReceiptEnvelopeV2<TrustedEventReceiptV2>,
) -> Result<(), String> {
    let binding = endpoint_binding(&config.config.endpoints, endpoint);
    validate_signed_envelope(receipt, &binding.principal_ref, verifier)?;
    if receipt.payload.schema_version != TRUSTED_EVENT_RECEIPT_V2
        || receipt.payload.sequence != sequence
        || receipt.payload.request_digest
            != sha256_json(request).map_err(|error| error.to_string())?
    {
        return Err("trusted event receipt is not bound to the exact dispatched event".into());
    }
    validate_phase_telemetry(
        &config.config.manifest,
        sequence,
        &receipt.payload.telemetry,
    )?;
    if endpoint != TrustedEndpointKindV2::Transport && !receipt.payload.transcript_delta.is_empty()
    {
        return Err("world and lifecycle controllers cannot add Slack transcript turns".into());
    }
    Ok(())
}

fn collect_authoritative_receipts(
    config: &ValidatedConfigV2<'_>,
    verifier: &dyn ReceiptSignatureVerifierV2,
    new_facts: &[SignedReceiptEnvelopeV2<AuthoritativeFactReceiptV2>],
    new_actions: &[SignedReceiptEnvelopeV2<AuthoritativeActionReceiptV2>],
    facts: &mut Vec<SignedReceiptEnvelopeV2<AuthoritativeFactReceiptV2>>,
    actions: &mut Vec<SignedReceiptEnvelopeV2<AuthoritativeActionReceiptV2>>,
) -> Result<(), String> {
    let world_principal = &config.config.principals.world_controller.principal_ref;
    let mut digests: BTreeSet<String> = facts
        .iter()
        .map(|receipt| receipt.payload_digest.clone())
        .chain(actions.iter().map(|receipt| receipt.payload_digest.clone()))
        .collect::<BTreeSet<_>>();
    let mut observation_refs = facts
        .iter()
        .map(|receipt| receipt.payload.observation_ref.clone())
        .collect::<BTreeSet<_>>();
    for fact in new_facts {
        validate_signed_envelope(fact, world_principal, verifier)?;
        validate_fact_receipt(&fact.payload)?;
        if !digests.insert(fact.payload_digest.clone())
            || !observation_refs.insert(fact.payload.observation_ref.clone())
        {
            return Err("authoritative fact receipt was duplicated".into());
        }
    }
    facts.extend_from_slice(new_facts);
    let known_observations: BTreeSet<String> = facts
        .iter()
        .map(|receipt| receipt.payload.observation_ref.clone())
        .collect::<BTreeSet<_>>();
    let mut action_refs = actions
        .iter()
        .map(|receipt| receipt.payload.action_ref.clone())
        .collect::<BTreeSet<_>>();
    for action in new_actions {
        validate_signed_envelope(action, world_principal, verifier)?;
        validate_action_receipt(&action.payload, &known_observations)?;
        if !digests.insert(action.payload_digest.clone())
            || !action_refs.insert(action.payload.action_ref.clone())
        {
            return Err("authoritative action receipt was duplicated".into());
        }
    }
    actions.extend_from_slice(new_actions);
    Ok(())
}

fn validate_signed_envelope<T: Serialize>(
    envelope: &SignedReceiptEnvelopeV2<T>,
    expected_principal_ref: &str,
    verifier: &dyn ReceiptSignatureVerifierV2,
) -> Result<(), String> {
    envelope.validate_digest_and_signature_shape()?;
    if envelope.schema_version != SIGNED_RECEIPT_ENVELOPE_V2
        || envelope.signer.principal_ref != expected_principal_ref
    {
        return Err("signed receipt signer does not match the trusted endpoint principal".into());
    }
    if !valid_base64_shape(&envelope.signature_base64) {
        return Err("signed receipt signature is not canonical base64-shaped data".into());
    }
    verifier.verify(
        &envelope.payload_digest,
        &envelope.signer,
        &envelope.signature_base64,
    )
}

fn validate_fact_receipt(receipt: &AuthoritativeFactReceiptV2) -> Result<(), String> {
    if receipt.schema_version != AUTHORITATIVE_FACT_RECEIPT_V2
        || [
            receipt.observation_ref.as_str(),
            receipt.world_instance_ref.as_str(),
            receipt.subject_ref.as_str(),
            receipt.predicate.as_str(),
            receipt.source_ref.as_str(),
            receipt.source_revision.as_str(),
        ]
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err("authoritative fact receipt is incomplete".into());
    }
    parse_time(&receipt.observed_at, "authoritative fact observation")?;
    if receipt.state == AuthoritativeEvidenceStateV2::Observed && !receipt.complete {
        return Err("an observed authoritative fact must declare complete scope".into());
    }
    Ok(())
}

fn validate_action_receipt(
    receipt: &AuthoritativeActionReceiptV2,
    known_observations: &BTreeSet<String>,
) -> Result<(), String> {
    if receipt.schema_version != AUTHORITATIVE_ACTION_RECEIPT_V2
        || [
            receipt.action_ref.as_str(),
            receipt.world_instance_ref.as_str(),
            receipt.actor_principal_ref.as_str(),
            receipt.authority_ref.as_str(),
            receipt.tool_id.as_str(),
            receipt.result_digest.as_str(),
        ]
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err("authoritative action receipt is incomplete".into());
    }
    require_sha256(&receipt.input_digest, "authoritative action input")?;
    require_sha256(&receipt.result_digest, "authoritative action result")?;
    parse_time(&receipt.occurred_at, "authoritative action occurrence")?;
    if receipt
        .verification_observation_refs
        .iter()
        .any(|reference| !known_observations.contains(reference.as_str()))
    {
        return Err("authoritative action cites an uncollected verification observation".into());
    }
    Ok(())
}

fn validate_phase_telemetry(
    manifest: &SealedEpisodeManifestV2,
    sequence: usize,
    telemetry: &ExchangePhaseTelemetryV2,
) -> Result<(), String> {
    if telemetry.exchange_sequence != sequence || telemetry.phases.is_empty() {
        return Err("phase telemetry is missing or bound to another sequence".into());
    }
    telemetry.validate_accounting()?;
    for phase in &telemetry.phases {
        let name = phase_name(phase.phase);
        let limit = manifest
            .limits
            .phase_latency_limits_ms
            .get(name)
            .ok_or_else(|| format!("phase {name} has no sealed latency budget"))?;
        if phase.budget_ms > *limit
            || phase.duration_ms > *limit
            || phase.outcome != PhaseOutcomeV2::Completed
        {
            return Err(format!("phase {name} failed or exceeded its sealed budget"));
        }
    }
    Ok(())
}

struct FinalAccountingV2<'a> {
    completed_event_count: usize,
    decisions: &'a [OperatorDecisionReceiptV2],
    criteria: &'a [OperatorCriterionStateV2],
    telemetry: &'a [EndpointPhaseTelemetryV2],
    facts: &'a [SignedReceiptEnvelopeV2<AuthoritativeFactReceiptV2>],
    actions: &'a [SignedReceiptEnvelopeV2<AuthoritativeActionReceiptV2>],
}

fn validate_final_accounting(
    config: &SupervisorExecutionConfigV2,
    accounting: FinalAccountingV2<'_>,
    defects: &mut Vec<DeterministicDefect>,
) {
    let expected_events = config.manifest.program.events.len();
    let has_terminal_defect = defects.iter().any(|defect| defect.terminal);
    if !has_terminal_defect
        && (accounting.completed_event_count != expected_events
            || accounting.decisions.len() != expected_events + 1
            || accounting.telemetry.len()
                != accounting.completed_event_count + accounting.decisions.len()
            || accounting
                .criteria
                .iter()
                .any(|criterion| criterion.status != CriterionStatusV2::Satisfied))
    {
        defects.push(terminal(
            "incomplete_execution_accounting",
            "Events, operator decisions, phase receipts, or final criteria were not completely accounted.",
        ));
    }
    let mut all_digests = BTreeSet::new();
    if accounting
        .facts
        .iter()
        .map(|receipt| receipt.payload_digest.as_str())
        .chain(
            accounting
                .actions
                .iter()
                .map(|receipt| receipt.payload_digest.as_str()),
        )
        .any(|digest| !all_digests.insert(digest))
    {
        defects.push(terminal(
            "duplicate_authoritative_receipt",
            "Authoritative fact and action receipt digests must be globally unique.",
        ));
    }
}

fn validate_config(config: &SupervisorExecutionConfigV2) -> Result<ValidatedConfigV2<'_>, String> {
    if config.manifest.schema_version != SEALED_EPISODE_MANIFEST_V2
        || config.manifest.program.schema_version
            != cerebro_slack_agent_eval_wire::EPISODE_EVENT_PROGRAM_V2
        || config.manifest.program.program_ref.trim().is_empty()
        || config.candidate_attestation_digest.trim().is_empty()
    {
        return Err("sealed supervisor configuration is incomplete".into());
    }
    require_sha256(
        &config.candidate_attestation_digest,
        "candidate attestation",
    )?;
    require_sha256(
        &config.assignment.holdout_assignment_commitment_digest,
        "holdout assignment commitment",
    )?;
    if config.assignment.assignment_alias.trim().is_empty()
        || config.assignment.comparison_pair_ref.trim().is_empty()
    {
        return Err("sealed supervisor assignment context is incomplete".into());
    }
    config.principals.validate_separation()?;
    if config.manifest.operator_controller.principal_ref != config.principals.operator.principal_ref
    {
        return Err("operator controller principal does not match execution principals".into());
    }
    validate_endpoint_binding(&config.endpoints.transport, &config.principals.candidate)?;
    validate_endpoint_binding(&config.endpoints.world, &config.principals.world_controller)?;
    validate_endpoint_binding(&config.endpoints.lifecycle, &config.principals.supervisor)?;
    validate_endpoint_binding(&config.endpoints.operator, &config.principals.operator)?;
    if config.manifest.limits.max_events == 0
        || config.manifest.program.events.len() > config.manifest.limits.max_events
        || config.manifest.limits.max_candidate_turns == 0
        || config.manifest.limits.candidate_turn_timeout_ms == 0
        || config.manifest.limits.operator_turn_timeout_ms == 0
        || config.manifest.limits.episode_timeout_ms == 0
        || config.manifest.limits.phase_latency_limits_ms.is_empty()
    {
        return Err("sealed episode limits are incomplete or exceeded".into());
    }
    validate_program_sequence(&config.manifest)?;
    validate_criteria(&config.initial_criteria)?;
    let aliases = validate_alias_bindings(config)?;
    Ok(ValidatedConfigV2 {
        config,
        manifest_digest: config
            .manifest
            .digest()
            .map_err(|error| error.to_string())?,
        aliases,
    })
}

fn validate_program_sequence(manifest: &SealedEpisodeManifestV2) -> Result<(), String> {
    let events = &manifest.program.events;
    SealedProgramCursorV2::new(events)?;
    let mut refs = BTreeSet::new();
    let mut previous_time = None;
    let mut previous_by_ref = BTreeMap::new();
    let mut expected_world_digest = manifest.world_digest.as_str();
    let mut candidate_turn_count = 0_usize;
    for event in events {
        let reference = event_ref(event);
        if reference.trim().is_empty() || !refs.insert(reference) {
            return Err("sealed events require unique non-empty references".into());
        }
        let event_time = event_time(event)?;
        if previous_time.is_some_and(|previous| event_time < previous) {
            return Err("sealed events are not chronologically ordered".into());
        }
        previous_time = Some(event_time);
        match event {
            ProgrammedEventV2::Correction {
                thread_alias,
                replaces_event_ref,
                ..
            } => match previous_by_ref.get(replaces_event_ref.as_str()) {
                Some(previous_thread) if previous_thread == thread_alias => {}
                _ => {
                    return Err(
                        "correction must replace an earlier candidate event in the same thread"
                            .into(),
                    );
                }
            },
            ProgrammedEventV2::ChangeWorld {
                world_before_digest,
                world_after_digest,
                ..
            } => {
                if world_before_digest != expected_world_digest
                    || world_after_digest.trim().is_empty()
                {
                    return Err(
                        "world mutation does not continue the sealed world digest chain".into(),
                    );
                }
                expected_world_digest = world_after_digest;
            }
            ProgrammedEventV2::Authorize { input_digest, .. } => {
                require_sha256(input_digest, "programmed authorization input")?;
            }
            ProgrammedEventV2::AdvanceClock { from, to, .. } => {
                let from = parse_time(from, "clock advance start")?;
                let to = parse_time(to, "clock advance end")?;
                if to <= from {
                    return Err("clock advance must move forward".into());
                }
            }
            _ => {}
        }
        if candidate_event_thread(event).is_some() {
            candidate_turn_count += 1;
        }
        if let Some(thread) = candidate_event_thread(event) {
            previous_by_ref.insert(reference, thread.to_owned());
        }
    }
    if candidate_turn_count > manifest.limits.max_candidate_turns {
        return Err("sealed program exceeds the candidate turn limit".into());
    }
    Ok(())
}

fn validate_alias_bindings(
    config: &SupervisorExecutionConfigV2,
) -> Result<BTreeMap<&str, &CandidateVisibleAliasesV2>, String> {
    let mut aliases = BTreeMap::new();
    let mut request_ids = BTreeSet::new();
    let mut delivery_refs = BTreeSet::new();
    for binding in &config.candidate_aliases {
        binding.aliases.validate()?;
        if aliases
            .insert(binding.event_ref.as_str(), &binding.aliases)
            .is_some()
            || !request_ids.insert(binding.aliases.request_id.as_str())
            || !delivery_refs.insert(binding.aliases.delivery_ref.as_str())
        {
            return Err("candidate event aliases must be unique".into());
        }
    }
    let expected = config
        .manifest
        .program
        .events
        .iter()
        .filter(|event| candidate_event_thread(event).is_some())
        .map(event_ref)
        .collect::<BTreeSet<_>>();
    if aliases.keys().copied().collect::<BTreeSet<_>>() != expected {
        return Err("candidate aliases do not exactly cover candidate-visible events".into());
    }
    for event in &config.manifest.program.events {
        let Some(thread) = candidate_event_thread(event) else {
            continue;
        };
        let event_aliases = aliases[event_ref(event)];
        if event_aliases.thread_ref != thread {
            return Err("candidate event thread alias does not match its sealed event".into());
        }
        match event {
            ProgrammedEventV2::Message { actor_alias, .. }
            | ProgrammedEventV2::Correction { actor_alias, .. }
            | ProgrammedEventV2::OpenThread { actor_alias, .. }
            | ProgrammedEventV2::Authorize { actor_alias, .. }
                if event_aliases.actor_ref != *actor_alias =>
            {
                return Err("candidate event actor alias does not match its sealed event".into());
            }
            ProgrammedEventV2::OpenThread {
                context_scope_alias,
                ..
            } if event_aliases.context_scope_ref.as_deref() != Some(context_scope_alias) => {
                return Err("open-thread context alias does not match its sealed event".into());
            }
            _ => {}
        }
    }
    Ok(aliases)
}

fn candidate_surface_event(
    event: &ProgrammedEventV2,
    aliases: &BTreeMap<&str, &CandidateVisibleAliasesV2>,
) -> Result<CandidateSurfaceEventV2, String> {
    let current = aliases
        .get(event_ref(event))
        .ok_or_else(|| "candidate-visible event has no alias binding".to_owned())?;
    let projected = match event {
        ProgrammedEventV2::Message { message, at, .. } => CandidateSurfaceEventV2::Message {
            aliases: (*current).clone(),
            message: message.clone(),
            at: at.clone(),
        },
        ProgrammedEventV2::Correction {
            replaces_event_ref,
            message,
            at,
            ..
        } => CandidateSurfaceEventV2::Correction {
            aliases: (*current).clone(),
            replaces_request_id: aliases
                .get(replaces_event_ref.as_str())
                .ok_or_else(|| "correction replacement has no candidate alias".to_owned())?
                .request_id
                .clone(),
            message: message.clone(),
            at: at.clone(),
        },
        ProgrammedEventV2::OpenThread { message, at, .. } => CandidateSurfaceEventV2::OpenThread {
            aliases: (*current).clone(),
            message: message.clone(),
            at: at.clone(),
        },
        ProgrammedEventV2::Wake {
            commitment_alias,
            occurrence_alias,
            at,
            ..
        } => CandidateSurfaceEventV2::Wake {
            aliases: (*current).clone(),
            commitment_ref: commitment_alias.clone(),
            occurrence_ref: occurrence_alias.clone(),
            at: at.clone(),
        },
        ProgrammedEventV2::Authorize {
            approval_alias,
            tool_id,
            input_digest,
            at,
            ..
        } => CandidateSurfaceEventV2::Authorize {
            aliases: (*current).clone(),
            approval_ref: approval_alias.clone(),
            tool_id: tool_id.clone(),
            input_digest: input_digest.clone(),
            at: at.clone(),
        },
        ProgrammedEventV2::ChangeWorld { .. }
        | ProgrammedEventV2::Restart { .. }
        | ProgrammedEventV2::AdvanceClock { .. } => {
            return Err("private control event cannot be projected to the candidate".into());
        }
    };
    projected.validate()?;
    Ok(projected)
}

fn ensure_candidate_surface_is_private(
    request: &CandidateTransportDispatchV2,
) -> Result<(), String> {
    let encoded = serde_json::to_string(request).map_err(|error| error.to_string())?;
    for private_marker in [
        "manifest_ref",
        "scenario_digest",
        "program_ref",
        "event_ref",
        "criteria_before",
        "episode_manifest_digest",
        "world_before_digest",
        "world_after_digest",
    ] {
        if encoded.contains(private_marker) {
            return Err(format!(
                "candidate transport dispatch exposes private field {private_marker}"
            ));
        }
    }
    Ok(())
}

async fn call_signed_endpoint<Request, Payload>(
    client: &Client,
    endpoint: &TrustedEndpointBindingV2,
    request: &Request,
    timeout_ms: u64,
) -> Result<SignedReceiptEnvelopeV2<Payload>, String>
where
    Request: Serialize + ?Sized,
    Payload: DeserializeOwned,
{
    let response = client
        .post(&endpoint.url)
        .timeout(Duration::from_millis(timeout_ms))
        .json(request)
        .send()
        .await
        .map_err(|error| bounded(error.to_string()))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|error| bounded(error.to_string()))?;
    if !status.is_success() {
        return Err(format!(
            "trusted endpoint returned {status}: {}",
            bounded(String::from_utf8_lossy(&body).into_owned())
        ));
    }
    serde_json::from_slice(&body).map_err(|error| bounded(error.to_string()))
}

fn validate_endpoint_binding(
    endpoint: &TrustedEndpointBindingV2,
    principal: &cerebro_slack_agent_eval_wire::RuntimePrincipalAttestationV2,
) -> Result<(), String> {
    if endpoint.url.trim().is_empty()
        || endpoint.principal_ref != principal.principal_ref
        || endpoint.endpoint_identity_digest != principal.endpoint_identity_digest
    {
        return Err("trusted endpoint binding does not match its attested principal".into());
    }
    Ok(())
}

fn endpoint_binding(
    endpoints: &TrustedExecutionEndpointsV2,
    endpoint: TrustedEndpointKindV2,
) -> &TrustedEndpointBindingV2 {
    match endpoint {
        TrustedEndpointKindV2::Transport => &endpoints.transport,
        TrustedEndpointKindV2::World => &endpoints.world,
        TrustedEndpointKindV2::Lifecycle => &endpoints.lifecycle,
        TrustedEndpointKindV2::Operator => &endpoints.operator,
    }
}

fn validate_criteria(criteria: &[OperatorCriterionStateV2]) -> Result<(), String> {
    let refs = criteria
        .iter()
        .map(|criterion| criterion.criterion_ref.as_str())
        .collect::<BTreeSet<_>>();
    if criteria.is_empty()
        || refs.len() != criteria.len()
        || refs.iter().any(|reference| reference.trim().is_empty())
    {
        return Err("initial deterministic criteria must be non-empty and unique".into());
    }
    Ok(())
}

fn event_ref(event: &ProgrammedEventV2) -> &str {
    match event {
        ProgrammedEventV2::Message { event_ref, .. }
        | ProgrammedEventV2::Correction { event_ref, .. }
        | ProgrammedEventV2::OpenThread { event_ref, .. }
        | ProgrammedEventV2::ChangeWorld { event_ref, .. }
        | ProgrammedEventV2::Restart { event_ref, .. }
        | ProgrammedEventV2::Wake { event_ref, .. }
        | ProgrammedEventV2::Authorize { event_ref, .. }
        | ProgrammedEventV2::AdvanceClock { event_ref, .. } => event_ref,
    }
}

fn candidate_event_thread(event: &ProgrammedEventV2) -> Option<&str> {
    match event {
        ProgrammedEventV2::Message { thread_alias, .. }
        | ProgrammedEventV2::Correction { thread_alias, .. }
        | ProgrammedEventV2::OpenThread { thread_alias, .. }
        | ProgrammedEventV2::Wake { thread_alias, .. }
        | ProgrammedEventV2::Authorize { thread_alias, .. } => Some(thread_alias),
        ProgrammedEventV2::ChangeWorld { .. }
        | ProgrammedEventV2::Restart { .. }
        | ProgrammedEventV2::AdvanceClock { .. } => None,
    }
}

fn event_time(event: &ProgrammedEventV2) -> Result<OffsetDateTime, String> {
    match event {
        ProgrammedEventV2::Message { at, .. }
        | ProgrammedEventV2::Correction { at, .. }
        | ProgrammedEventV2::OpenThread { at, .. }
        | ProgrammedEventV2::ChangeWorld { at, .. }
        | ProgrammedEventV2::Restart { at, .. }
        | ProgrammedEventV2::Wake { at, .. }
        | ProgrammedEventV2::Authorize { at, .. } => parse_time(at, "programmed event"),
        ProgrammedEventV2::AdvanceClock { to, .. } => parse_time(to, "clock advance"),
    }
}

fn phase_name(phase: ExecutionPhaseV2) -> &'static str {
    match phase {
        ExecutionPhaseV2::Ingress => "ingress",
        ExecutionPhaseV2::SessionLoad => "session_load",
        ExecutionPhaseV2::LeaseAcquire => "lease_acquire",
        ExecutionPhaseV2::Route => "route",
        ExecutionPhaseV2::Operate => "operate",
        ExecutionPhaseV2::Tool => "tool",
        ExecutionPhaseV2::Critique => "critique",
        ExecutionPhaseV2::Present => "present",
        ExecutionPhaseV2::Journal => "journal",
        ExecutionPhaseV2::Render => "render",
        ExecutionPhaseV2::Deliver => "deliver",
        ExecutionPhaseV2::RestartRecovery => "restart_recovery",
        ExecutionPhaseV2::Operator => "operator",
    }
}

fn require_candidate_alias(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} alias is empty"));
    }
    let normalized = value.to_ascii_lowercase();
    let forbidden = ["blackbox", "eval", "holdout", "scenario", "candidate"];
    if forbidden.iter().any(|marker| normalized.contains(marker)) {
        return Err(format!("{label} alias discloses evaluator state"));
    }
    Ok(())
}

fn require_visible_text(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 16 * 1024 {
        return Err(format!("{label} is empty or oversized"));
    }
    Ok(())
}

fn require_sha256(value: &str, label: &str) -> Result<(), String> {
    if !value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err(format!("{label} digest is not canonical SHA-256"));
    }
    Ok(())
}

fn parse_time(value: &str, label: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| format!("{label} timestamp is invalid"))
}

fn valid_base64_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return false;
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    padding <= 2
        && bytes[..bytes.len() - padding]
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
        && bytes[bytes.len() - padding..]
            .iter()
            .copied()
            .all(|byte| byte == b'=')
}

fn episode_timed_out(started: tokio::time::Instant, timeout_ms: u64) -> bool {
    started.elapsed() > Duration::from_millis(timeout_ms)
}

fn terminal(code: &str, detail: impl Into<String>) -> DeterministicDefect {
    DeterministicDefect {
        code: code.into(),
        detail: bounded(detail.into()),
        terminal: true,
    }
}

fn bounded(value: String) -> String {
    value.chars().take(MAX_ERROR_CHARS).collect()
}

fn now() -> Result<String, String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebro_slack_agent_eval_wire::{
        EPISODE_EVENT_PROGRAM_V2, EpisodeEventProgramV2, EpisodeLimitsV2,
        OperatorControllerAttestationV2, RestartTargetV2, RuntimePrincipalAttestationV2,
        SurfaceGeneratorAttestationV2,
    };

    fn message(event_ref: &str, at: &str) -> ProgrammedEventV2 {
        ProgrammedEventV2::Message {
            event_ref: event_ref.into(),
            thread_alias: "slack-thread://T01/C01/1710000000.000001".into(),
            actor_alias: "slack-user://U01".into(),
            message: "Please check the current user path.".into(),
            at: at.into(),
        }
    }

    fn manifest(events: Vec<ProgrammedEventV2>) -> SealedEpisodeManifestV2 {
        SealedEpisodeManifestV2 {
            schema_version: SEALED_EPISODE_MANIFEST_V2.into(),
            manifest_ref: "private-manifest:one".into(),
            scenario_digest: format!("sha256:{}", "1".repeat(64)),
            generator: SurfaceGeneratorAttestationV2 {
                generator_ref: "generator:one".into(),
                artifact_digest: format!("sha256:{}", "2".repeat(64)),
                semantic_template_digest: format!("sha256:{}", "3".repeat(64)),
                surface_seed_commitment: format!("sha256:{}", "4".repeat(64)),
            },
            program: EpisodeEventProgramV2 {
                schema_version: EPISODE_EVENT_PROGRAM_V2.into(),
                program_ref: "private-program:one".into(),
                events,
            },
            limits: EpisodeLimitsV2 {
                max_events: 8,
                max_candidate_turns: 8,
                candidate_turn_timeout_ms: 120_000,
                operator_turn_timeout_ms: 30_000,
                episode_timeout_ms: 600_000,
                phase_latency_limits_ms: BTreeMap::from([
                    ("operator".into(), 30_000),
                    ("route".into(), 20_000),
                ]),
            },
            world_digest: format!("sha256:{}", "5".repeat(64)),
            operator_controller: OperatorControllerAttestationV2 {
                controller_ref: "controller:one".into(),
                artifact_digest: format!("sha256:{}", "6".repeat(64)),
                policy_digest: format!("sha256:{}", "7".repeat(64)),
                principal_ref: "principal:operator".into(),
            },
            candidate_surface_contract_digest: format!("sha256:{}", "8".repeat(64)),
        }
    }

    fn aliases(request_id: &str) -> CandidateVisibleAliasesV2 {
        CandidateVisibleAliasesV2 {
            tenant_id: "slack-workspace://W01".into(),
            request_id: request_id.into(),
            thread_ref: "slack-thread://T01/C01/1710000000.000001".into(),
            actor_ref: "slack-user://U01".into(),
            context_scope_ref: Some("slack-context-scope://W01/C01".into()),
            delivery_ref: format!("slack-delivery://{request_id}"),
        }
    }

    #[test]
    fn sealed_cursor_rejects_out_of_order_and_missing_events() {
        let events = vec![
            message("private-event:one", "2026-08-03T00:00:00Z"),
            message("private-event:two", "2026-08-03T00:01:00Z"),
        ];
        validate_program_sequence(&manifest(events.clone())).unwrap();
        let mut cursor = SealedProgramCursorV2::new(&events).unwrap();
        assert!(cursor.accept(&events[1]).is_err());
        assert!(!cursor.is_complete());
        cursor.accept(&events[0]).unwrap();
        assert!(!cursor.is_complete());
        cursor.accept(&events[1]).unwrap();
        assert!(cursor.is_complete());
        assert!(cursor.accept(&events[1]).is_err());
    }

    #[test]
    fn candidate_surface_rejects_alias_leaks_and_omits_private_fields() {
        let event = message("private-event:one", "2026-08-03T00:00:00Z");
        let good = aliases("slack-event://E01");
        let bindings = BTreeMap::from([("private-event:one", &good)]);
        let projected = candidate_surface_event(&event, &bindings).unwrap();
        let dispatch = CandidateTransportDispatchV2 {
            schema_version: TRANSPORT_DISPATCH_V2.into(),
            candidate_event: projected,
        };
        ensure_candidate_surface_is_private(&dispatch).unwrap();
        let encoded = serde_json::to_string(&dispatch).unwrap();
        assert!(!encoded.contains("private-event:one"));
        assert!(!encoded.contains("manifest_ref"));
        assert!(!encoded.contains("program_ref"));

        let leaked = aliases("blackbox-request:one");
        let leaked_bindings = BTreeMap::from([("private-event:one", &leaked)]);
        assert!(candidate_surface_event(&event, &leaked_bindings).is_err());
    }

    #[test]
    fn execution_principals_fixture_remains_separated() {
        let principal = |name: &str| RuntimePrincipalAttestationV2 {
            principal_ref: format!("principal:{name}"),
            artifact_digest: format!("sha256:{name}-artifact"),
            endpoint_identity_digest: format!("sha256:{name}-endpoint"),
        };
        let principals = ExecutionPrincipalsV2 {
            schema_version: cerebro_slack_agent_eval_wire::EXECUTION_PRINCIPALS_V2.into(),
            supervisor: principal("supervisor"),
            candidate: principal("candidate-runtime"),
            operator: principal("operator"),
            world_controller: principal("world"),
        };
        assert!(principals.validate_separation().is_ok());
    }

    #[test]
    fn restart_targets_remain_private_control_events() {
        let restart = ProgrammedEventV2::Restart {
            event_ref: "private-event:restart".into(),
            target: RestartTargetV2::CandidateRuntime,
            at: "2026-08-03T00:02:00Z".into(),
        };
        assert!(candidate_event_thread(&restart).is_none());
    }
}
