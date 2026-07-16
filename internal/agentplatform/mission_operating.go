package agentplatform

type MissionOperatingContract struct {
	ID                   string                  `json:"id"`
	Purpose              string                  `json:"purpose"`
	SchemaVersion        string                  `json:"schema_version"`
	DurableRecords       []MissionRecordContract `json:"durable_records"`
	ExecutionDepths      []string                `json:"execution_depths"`
	SupervisorDirectives []string                `json:"supervisor_directives"`
	WakeConditions       []string                `json:"wake_conditions"`
	InterruptionTriggers []string                `json:"interruption_triggers"`
	CloseConditions      []string                `json:"close_conditions"`
	FirstMandate         string                  `json:"first_mandate"`
}

type MissionRecordContract struct {
	ID       string   `json:"id"`
	Purpose  string   `json:"purpose"`
	Required []string `json:"required"`
}

func missionOperatingContract() MissionOperatingContract {
	return MissionOperatingContract{
		ID:            "native-mission-operating-contract",
		Purpose:       "Keep one objective, beliefs, plan revisions, commitments, wake conditions, authority, and verification state durable across agent runs.",
		SchemaVersion: "cerebro.control-kernel.v1",
		DurableRecords: []MissionRecordContract{
			{ID: "mandate", Purpose: "Define the desired condition, scope, maximum violation age, and lifecycle revision.", Required: []string{"mandate_id", "revision", "desired_condition", "scope_urns", "maximum_violation_age_seconds", "status"}},
			{ID: "mission", Purpose: "Track one unresolved difference between observed state and the mandate.", Required: []string{"mission_id", "mandate_id", "mandate_revision", "objective", "subject_urns", "state", "revision"}},
			{ID: "belief", Purpose: "Preserve a versioned statement with support, contradiction, gaps, confidence, source revision, and invalidation conditions.", Required: []string{"belief_id", "revision", "statement", "basis", "verdict", "subject_urns", "invalidation_conditions"}},
			{ID: "plan_revision", Purpose: "Bind immutable capability steps to the beliefs they test or change.", Required: []string{"plan_id", "revision", "rationale", "hypothesis_ids", "steps", "created_by"}},
			{ID: "commitment", Purpose: "Bind one plan step to an actor, capability, target, expected effect, authority, rollback, and receipts.", Required: []string{"commitment_id", "plan_id", "plan_revision", "actor_id", "capability", "resource_urn", "expected_effect", "state"}},
			{ID: "wake_condition", Purpose: "Name the exact source change, event, deadline, conversation, or decision that resumes work.", Required: []string{"wake_condition_id", "kind", "state", "armed_at_unix_ms", "reason"}},
		},
		ExecutionDepths: []string{"read_current_state", "targeted_verification", "deep_investigation"},
		SupervisorDirectives: []string{
			"resolve_scope",
			"revise_plan",
			"request_decision",
			"execute",
			"verify",
			"wait",
			"replan_from_wake",
			"blocked",
			"close",
			"no_action",
		},
		WakeConditions: []string{"source_revision_changed", "event_observed", "deadline_reached", "conversation_advanced", "decision_recorded"},
		InterruptionTriggers: []string{
			"exact decision required",
			"evidence invalidated the current plan",
			"authority or execution budget exhausted",
			"mission blocked without a valid wake condition",
			"desired condition independently verified",
			"previously verified condition became false",
		},
		CloseConditions: []string{
			"all commitments are fulfilled or cancelled",
			"no wake condition remains armed",
			"verifier differs from executor",
			"observed source revision differs from the pre-action revision",
			"verification cites at least one evidence URN",
		},
		FirstMandate: "No terminated identity retains production access for more than 24 hours.",
	}
}

func cloneMissionOperatingContract(contract MissionOperatingContract) MissionOperatingContract {
	contract.DurableRecords = append([]MissionRecordContract(nil), contract.DurableRecords...)
	for index := range contract.DurableRecords {
		contract.DurableRecords[index].Required = cloneStrings(contract.DurableRecords[index].Required)
	}
	contract.ExecutionDepths = cloneStrings(contract.ExecutionDepths)
	contract.SupervisorDirectives = cloneStrings(contract.SupervisorDirectives)
	contract.WakeConditions = cloneStrings(contract.WakeConditions)
	contract.InterruptionTriggers = cloneStrings(contract.InterruptionTriggers)
	contract.CloseConditions = cloneStrings(contract.CloseConditions)
	return contract
}
