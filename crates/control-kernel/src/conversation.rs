use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{MissionId, MissionState};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionDepth {
    ReadCurrentState,
    TargetedVerification,
    DeepInvestigation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncounterProfile {
    pub is_follow_up: bool,
    pub explicit_deep_request: bool,
    pub consequential_action_requested: bool,
    pub current_state_available: bool,
    pub current_state_fresh: bool,
    pub material_evidence_gap: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MissionReference {
    pub mission_id: MissionId,
    pub state: MissionState,
    pub subject_urns: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "resolution", rename_all = "snake_case")]
pub enum ConversationResolution {
    ContinueMission {
        mission_id: MissionId,
    },
    OpenMission,
    NeedsMissionChoice {
        candidate_mission_ids: Vec<MissionId>,
    },
    UnknownMissionReference {
        mission_id: MissionId,
    },
}

pub fn route_execution_depth(profile: &EncounterProfile) -> ExecutionDepth {
    if profile.explicit_deep_request
        || (profile.consequential_action_requested && profile.material_evidence_gap)
    {
        return ExecutionDepth::DeepInvestigation;
    }
    if profile.current_state_available
        && profile.current_state_fresh
        && !profile.material_evidence_gap
        && profile.is_follow_up
    {
        return ExecutionDepth::ReadCurrentState;
    }
    ExecutionDepth::TargetedVerification
}

pub fn resolve_conversation(
    explicit_mission_id: Option<&MissionId>,
    subject_urns: &[String],
    missions: &[MissionReference],
) -> ConversationResolution {
    if let Some(explicit) = explicit_mission_id {
        return missions
            .iter()
            .find(|mission| &mission.mission_id == explicit)
            .map(|mission| ConversationResolution::ContinueMission {
                mission_id: mission.mission_id.clone(),
            })
            .unwrap_or_else(|| ConversationResolution::UnknownMissionReference {
                mission_id: explicit.clone(),
            });
    }
    let requested_subjects = subject_urns.iter().collect::<BTreeSet<_>>();
    let mut candidates = missions
        .iter()
        .filter(|mission| !matches!(mission.state, MissionState::Closed))
        .filter(|mission| {
            mission
                .subject_urns
                .iter()
                .any(|subject| requested_subjects.contains(subject))
        })
        .map(|mission| mission.mission_id.clone())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    match candidates.as_slice() {
        [] => ConversationResolution::OpenMission,
        [mission_id] => ConversationResolution::ContinueMission {
            mission_id: mission_id.clone(),
        },
        _ => ConversationResolution::NeedsMissionChoice {
            candidate_mission_ids: candidates,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_fresh_follow_ups_do_not_launch_research() {
        assert_eq!(
            route_execution_depth(&EncounterProfile {
                is_follow_up: true,
                explicit_deep_request: false,
                consequential_action_requested: false,
                current_state_available: true,
                current_state_fresh: true,
                material_evidence_gap: false,
            }),
            ExecutionDepth::ReadCurrentState
        );
    }

    #[test]
    fn subject_overlap_continues_existing_work() {
        let mission_id = MissionId::parse("mission-1").unwrap();
        let resolution = resolve_conversation(
            None,
            &["urn:identity:1".into()],
            &[MissionReference {
                mission_id: mission_id.clone(),
                state: MissionState::WaitingOnEvidence,
                subject_urns: vec!["urn:identity:1".into()],
            }],
        );
        assert_eq!(
            resolution,
            ConversationResolution::ContinueMission { mission_id }
        );
    }
}
