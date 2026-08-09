use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{MissionId, MissionState};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Bounded evidence-collection effort selected for one encounter.
pub enum ExecutionDepth {
    /// Reuse an available fresh observation without launching new research.
    ReadCurrentState,
    /// Perform focused reads needed to refresh or verify the requested fact.
    TargetedVerification,
    /// Investigate broadly because the request is explicit or error cost is high.
    DeepInvestigation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Deterministic facts used to choose encounter execution depth.
pub struct EncounterProfile {
    /// Whether the encounter continues recent conversation rather than starting work.
    pub is_follow_up: bool,
    /// Whether the operator explicitly requested deep or exhaustive investigation.
    pub explicit_deep_request: bool,
    /// Whether the requested outcome can materially change external state.
    pub consequential_action_requested: bool,
    /// Whether a current-state observation is already available.
    pub current_state_available: bool,
    /// Whether that observation remains within its declared freshness window.
    pub current_state_fresh: bool,
    /// Whether a known evidence gap could change the answer or safe action.
    pub material_evidence_gap: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Minimal mission projection used to route a conversation encounter.
pub struct MissionReference {
    /// Stable mission identity returned by a continuation resolution.
    pub mission_id: MissionId,
    /// Current lifecycle state used to exclude closed work from implicit matching.
    pub state: MissionState,
    /// Canonical subjects used for exact-overlap matching.
    pub subject_urns: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "resolution", rename_all = "snake_case")]
/// Deterministic decision connecting an encounter to durable mission state.
pub enum ConversationResolution {
    /// Exactly one usable mission was selected.
    ContinueMission {
        /// Existing mission that should receive the encounter.
        mission_id: MissionId,
    },
    /// No active mission matched, so the caller should open new work.
    OpenMission,
    /// Multiple active missions matched and require an explicit operator choice.
    NeedsMissionChoice {
        /// Sorted, deduplicated candidate mission identifiers.
        candidate_mission_ids: Vec<MissionId>,
    },
    /// An explicit mission identifier was supplied but is absent from the candidates.
    UnknownMissionReference {
        /// Unresolved identifier supplied by the operator or transport.
        mission_id: MissionId,
    },
}

/// Selects the smallest safe evidence-collection depth for an encounter.
///
/// Explicit deep requests always win. Consequential actions with material evidence
/// gaps also require deep investigation. Only a follow-up with available, fresh,
/// complete-enough current state may reuse that state directly; every other case
/// receives targeted verification.
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

/// Resolves an encounter to an existing mission, new mission, or explicit choice.
///
/// An explicit mission reference is authoritative and never falls back to subject
/// matching. Without one, only non-closed missions sharing at least one exact
/// canonical subject URN are candidates. Candidate identifiers are sorted and
/// deduplicated so resolution is independent of storage order.
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

    fn mission(id: &str, state: MissionState, subjects: &[&str]) -> MissionReference {
        MissionReference {
            mission_id: MissionId::parse(id).unwrap(),
            state,
            subject_urns: subjects.iter().map(|subject| (*subject).into()).collect(),
        }
    }

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

    #[test]
    fn execution_depth_tracks_the_cost_of_being_wrong() {
        let mut profile = EncounterProfile {
            is_follow_up: false,
            explicit_deep_request: false,
            consequential_action_requested: false,
            current_state_available: false,
            current_state_fresh: false,
            material_evidence_gap: false,
        };
        assert_eq!(
            route_execution_depth(&profile),
            ExecutionDepth::TargetedVerification
        );
        profile.explicit_deep_request = true;
        assert_eq!(
            route_execution_depth(&profile),
            ExecutionDepth::DeepInvestigation
        );
        profile.explicit_deep_request = false;
        profile.consequential_action_requested = true;
        profile.material_evidence_gap = true;
        assert_eq!(
            route_execution_depth(&profile),
            ExecutionDepth::DeepInvestigation
        );
    }

    #[test]
    fn conversation_resolution_is_explicit_and_deterministic() {
        let first = mission("mission-1", MissionState::Planning, &["urn:identity:1"]);
        let second = mission(
            "mission-2",
            MissionState::WaitingOnEvidence,
            &["urn:identity:1"],
        );
        let closed = mission("mission-3", MissionState::Closed, &["urn:identity:2"]);

        assert_eq!(
            resolve_conversation(Some(&first.mission_id), &[], std::slice::from_ref(&first)),
            ConversationResolution::ContinueMission {
                mission_id: first.mission_id.clone()
            }
        );
        let missing = MissionId::parse("mission-missing").unwrap();
        assert_eq!(
            resolve_conversation(Some(&missing), &[], std::slice::from_ref(&first)),
            ConversationResolution::UnknownMissionReference {
                mission_id: missing
            }
        );
        assert_eq!(
            resolve_conversation(None, &["urn:identity:2".into()], &[closed]),
            ConversationResolution::OpenMission
        );
        assert_eq!(
            resolve_conversation(
                None,
                &["urn:identity:1".into()],
                &[second.clone(), first.clone(), second.clone()],
            ),
            ConversationResolution::NeedsMissionChoice {
                candidate_mission_ids: vec![first.mission_id, second.mission_id]
            }
        );
    }
}
