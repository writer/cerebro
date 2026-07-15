use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    ActorId, AuthorizationDecision, AuthorizationRequest, DecisionReceipt, Mission, MissionId,
    MissionInput, MissionState, RequestId, TenantId, VerificationReceipt,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandEnvelope {
    pub schema_version: String,
    pub request_id: RequestId,
    pub tenant_id: TenantId,
    pub command: ControlCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ControlCommand {
    OpenMission {
        input: MissionInput,
    },
    AdvanceMission {
        tenant_id: TenantId,
        mission_id: MissionId,
        expected_revision: u64,
        to: MissionState,
        actor_id: ActorId,
        reason: String,
    },
    Authorize {
        request: AuthorizationRequest,
    },
    RecordDecision {
        tenant_id: TenantId,
        mission_id: MissionId,
        expected_proposal_digest: String,
        receipt: DecisionReceipt,
    },
    RecordVerification {
        tenant_id: TenantId,
        mission_id: MissionId,
        receipt: VerificationReceipt,
    },
}

impl ControlCommand {
    pub fn tenant_id(&self) -> &TenantId {
        match self {
            Self::OpenMission { input } => &input.tenant_id,
            Self::AdvanceMission { tenant_id, .. }
            | Self::RecordDecision { tenant_id, .. }
            | Self::RecordVerification { tenant_id, .. } => tenant_id,
            Self::Authorize { request } => &request.tenant_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ControlResponse {
    Mission { mission: Mission },
    Authorization { decision: AuthorizationDecision },
    Accepted { request_id: RequestId },
    Rejected { code: String, message: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    UnsupportedSchema,
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
