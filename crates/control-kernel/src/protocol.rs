use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    ActorId, AuthorizationDecision, AuthorizationRequest, BeliefId, BeliefInput, BeliefRevision,
    CommitmentId, CommitmentInput, CommitmentTransition, ConversationResolution, DecisionReceipt,
    EncounterProfile, ExecutionDepth, Mission, MissionDirective, MissionId, MissionInput,
    MissionReference, MissionState, PlanRevision, RequestId, SupervisorSnapshot, TenantId,
    VerificationReceipt, WakeConditionId, WakeConditionKind, WakeSignal,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Versioned, tenant-bound request envelope for the control-kernel wire protocol.
pub struct CommandEnvelope {
    /// Must equal [`crate::SCHEMA_VERSION`].
    pub schema_version: String,
    /// Stable correlation and idempotency identity supplied by the caller.
    pub request_id: RequestId,
    /// Tenant boundary that must equal the command payload's tenant.
    pub tenant_id: TenantId,
    /// Pure domain command to validate and dispatch.
    pub command: ControlCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
/// Provider-neutral command accepted by a control-kernel host adapter.
pub enum ControlCommand {
    /// Opens revision one of a mission.
    OpenMission {
        /// Exact tenant, mandate, objective, subjects, and actor bindings.
        input: MissionInput,
    },
    /// Applies one optimistic mission lifecycle transition.
    AdvanceMission {
        /// Tenant owning the mission.
        tenant_id: TenantId,
        /// Mission to update.
        mission_id: MissionId,
        /// Revision observed by the caller.
        expected_revision: u64,
        /// Requested next state.
        to: MissionState,
        /// Actor responsible for the transition.
        actor_id: ActorId,
        /// Bounded transition reason.
        reason: String,
    },
    /// Evaluates one exact request against capability authority.
    Authorize {
        /// Tenant-, actor-, action-, resource-, and time-bound request.
        request: AuthorizationRequest,
    },
    /// Records an approval decision for an exact proposal digest.
    RecordDecision {
        /// Tenant owning the mission.
        tenant_id: TenantId,
        /// Mission waiting on the decision.
        mission_id: MissionId,
        /// Digest of the proposal the host expects was reviewed.
        expected_proposal_digest: String,
        /// Approval-system receipt to authenticate and bind.
        receipt: DecisionReceipt,
    },
    /// Records an independent post-effect verification receipt.
    RecordVerification {
        /// Tenant owning the mission.
        tenant_id: TenantId,
        /// Mission currently in verification.
        mission_id: MissionId,
        /// Independent source observation.
        receipt: VerificationReceipt,
    },
    /// Creates an evidence-bounded belief within a mission.
    RecordBelief {
        /// Tenant owning the mission.
        tenant_id: TenantId,
        /// Mission receiving the belief.
        mission_id: MissionId,
        /// Initial belief snapshot.
        input: BeliefInput,
    },
    /// Replaces an existing belief's evidence judgment.
    ReviseBelief {
        /// Tenant owning the mission.
        tenant_id: TenantId,
        /// Mission containing the belief.
        mission_id: MissionId,
        /// Belief to revise.
        belief_id: BeliefId,
        /// Optimistic replacement snapshot.
        revision: BeliefRevision,
    },
    /// Appends a contiguous execution-plan revision.
    RevisePlan {
        /// Tenant owning the mission.
        tenant_id: TenantId,
        /// Mission receiving the plan.
        mission_id: MissionId,
        /// Immutable plan revision.
        revision: PlanRevision,
    },
    /// Creates a commitment from an existing plan step.
    ProposeCommitment {
        /// Tenant owning the mission.
        tenant_id: TenantId,
        /// Mission containing the plan.
        mission_id: MissionId,
        /// Immutable commitment bindings.
        input: CommitmentInput,
    },
    /// Applies an authority- and receipt-gated commitment transition.
    TransitionCommitment {
        /// Tenant owning the mission.
        tenant_id: TenantId,
        /// Mission containing the commitment.
        mission_id: MissionId,
        /// Commitment to update.
        commitment_id: CommitmentId,
        /// Optimistic requested transition.
        transition: CommitmentTransition,
    },
    /// Creates an armed future-observation condition.
    ArmWakeCondition {
        /// Tenant owning the mission.
        tenant_id: TenantId,
        /// Mission that will resume.
        mission_id: MissionId,
        /// Stable condition identity.
        wake_condition_id: WakeConditionId,
        /// Exact signal predicate.
        kind: WakeConditionKind,
        /// Bounded reason the mission is waiting.
        reason: String,
    },
    /// Applies a signal to an existing armed wake condition.
    SatisfyWakeCondition {
        /// Tenant owning the mission.
        tenant_id: TenantId,
        /// Mission containing the condition.
        mission_id: MissionId,
        /// Armed condition to evaluate.
        wake_condition_id: WakeConditionId,
        /// Observed signal.
        signal: WakeSignal,
    },
    /// Terminally cancels an armed wake condition.
    CancelWakeCondition {
        /// Tenant owning the mission.
        tenant_id: TenantId,
        /// Mission containing the condition.
        mission_id: MissionId,
        /// Armed condition to cancel.
        wake_condition_id: WakeConditionId,
        /// Bounded cancellation reason.
        reason: String,
    },
    /// Chooses execution depth from encounter risk and evidence characteristics.
    RouteEncounter {
        /// Tenant in which the encounter occurred.
        tenant_id: TenantId,
        /// Deterministic routing inputs.
        profile: EncounterProfile,
    },
    /// Resolves whether conversation starts, continues, or needs clarification.
    ResolveConversation {
        /// Tenant boundary for all candidate missions.
        tenant_id: TenantId,
        /// Explicit operator mission reference, when supplied.
        explicit_mission_id: Option<MissionId>,
        /// Canonical subjects mentioned by the encounter.
        subject_urns: Vec<String>,
        /// Candidate mission summaries visible to the resolver.
        missions: Vec<MissionReference>,
    },
    /// Computes the next bounded directive from a mission snapshot.
    EvaluateMission {
        /// Tenant owning the mission.
        tenant_id: TenantId,
        /// Mission being supervised.
        mission_id: MissionId,
        /// Current child-record and pending-decision state.
        snapshot: SupervisorSnapshot,
    },
}

impl ControlCommand {
    /// Returns the tenant carried by the command payload.
    ///
    /// [`CommandEnvelope::validate`] compares this value with the outer envelope
    /// so dispatch cannot route a payload across tenant boundaries.
    pub fn tenant_id(&self) -> &TenantId {
        match self {
            Self::OpenMission { input } => &input.tenant_id,
            Self::AdvanceMission { tenant_id, .. }
            | Self::RecordDecision { tenant_id, .. }
            | Self::RecordVerification { tenant_id, .. }
            | Self::RecordBelief { tenant_id, .. }
            | Self::ReviseBelief { tenant_id, .. }
            | Self::RevisePlan { tenant_id, .. }
            | Self::ProposeCommitment { tenant_id, .. }
            | Self::TransitionCommitment { tenant_id, .. }
            | Self::ArmWakeCondition { tenant_id, .. }
            | Self::SatisfyWakeCondition { tenant_id, .. }
            | Self::CancelWakeCondition { tenant_id, .. }
            | Self::RouteEncounter { tenant_id, .. }
            | Self::ResolveConversation { tenant_id, .. }
            | Self::EvaluateMission { tenant_id, .. } => tenant_id,
            Self::Authorize { request } => &request.tenant_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
/// Provider-neutral result returned by a control-kernel host adapter.
pub enum ControlResponse {
    /// Returns the latest mission snapshot.
    Mission { mission: Mission },
    /// Returns a fail-closed capability decision.
    Authorization { decision: AuthorizationDecision },
    /// Returns deterministic encounter execution depth.
    ExecutionDepth { depth: ExecutionDepth },
    /// Returns deterministic conversation-to-mission resolution.
    Conversation { resolution: ConversationResolution },
    /// Returns the supervisor's next bounded mission action.
    Directive { directive: MissionDirective },
    /// Confirms asynchronous acceptance under the supplied request identity.
    Accepted { request_id: RequestId },
    /// Returns a bounded machine code and operator-readable failure.
    Rejected { code: String, message: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Envelope-level validation failure before command dispatch.
pub enum ProtocolError {
    /// Envelope schema does not match this kernel revision.
    UnsupportedSchema,
    /// Outer tenant differs from the command payload tenant.
    TenantMismatch,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema => formatter.write_str("control command schema is unsupported"),
            Self::TenantMismatch => {
                formatter.write_str("control command tenant does not match envelope")
            }
        }
    }
}

impl Error for ProtocolError {}

impl CommandEnvelope {
    /// Validates schema compatibility and the outer-to-inner tenant binding.
    ///
    /// Domain fields are validated by their owning aggregate when dispatched;
    /// this method only establishes that the envelope can be safely routed.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema_version != crate::SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema);
        }
        if self.tenant_id != *self.command.tenant_id() {
            return Err(ProtocolError::TenantMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MandateId;

    fn envelope() -> CommandEnvelope {
        let tenant_id = TenantId::parse("tenant-1").unwrap();
        CommandEnvelope {
            schema_version: crate::SCHEMA_VERSION.into(),
            request_id: RequestId::parse("request-1").unwrap(),
            tenant_id: tenant_id.clone(),
            command: ControlCommand::OpenMission {
                input: MissionInput {
                    tenant_id,
                    mission_id: MissionId::parse("mission-1").unwrap(),
                    mandate_id: MandateId::parse("mandate-1").unwrap(),
                    mandate_revision: 1,
                    objective: "Remove stale access".into(),
                    subject_urns: vec!["urn:identity:1".into()],
                    actor_id: ActorId::parse("agent-1").unwrap(),
                },
            },
        }
    }

    #[test]
    fn command_envelopes_bind_schema_and_tenant() {
        assert_eq!(envelope().validate(), Ok(()));

        let mut wrong_schema = envelope();
        wrong_schema.schema_version = "cerebro.control-kernel.v2".into();
        assert_eq!(
            wrong_schema.validate(),
            Err(ProtocolError::UnsupportedSchema)
        );

        let mut wrong_tenant = envelope();
        wrong_tenant.tenant_id = TenantId::parse("tenant-2").unwrap();
        assert_eq!(wrong_tenant.validate(), Err(ProtocolError::TenantMismatch));
    }
}
