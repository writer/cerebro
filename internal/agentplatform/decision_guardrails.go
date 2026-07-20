package agentplatform

const (
	AgentReadinessReady             = "ready"
	AgentReadinessReadyWithWarnings = "ready_with_warnings"
	AgentReadinessBlocked           = "blocked"
)

// AgentDecisionGuardrails is the reusable policy projection applied before a
// caller reasons about a decision. Readiness describes whether the agent may
// proceed; it does not describe confidence in a decision outcome.
type AgentDecisionGuardrails struct {
	Version            string                      `json:"version"`
	Preflight          AgentRunPreflight           `json:"preflight"`
	VerifierResults    []AgentVerifierResult       `json:"verifier_results"`
	ActionLadder       []AgentActionStageStatus    `json:"action_ladder"`
	ConnectorToolGates []ConnectorToolGateDecision `json:"connector_tool_gates"`
	Readiness          AgentReadinessAssessment    `json:"readiness"`
	RequiredWriteBack  []string                    `json:"required_write_back"`
}

type AgentReadinessAssessment struct {
	State   string   `json:"state"`
	Reasons []string `json:"reasons"`
}

// BuildAgentDecisionGuardrails applies the existing preflight, verifier,
// connector, and action policies without loading or resolving decision facts.
func BuildAgentDecisionGuardrails(request EvidencePacketRequest) AgentDecisionGuardrails {
	request = normalizeEvidencePacketRequest(request)
	preflight := PreflightAgentRun(AgentRunPreflightRequest{
		TenantID:              request.TenantID,
		ActorID:               request.ActorID,
		CapabilityIDs:         request.CapabilityIDs,
		Question:              request.Question,
		ScopeURN:              request.ScopeURN,
		Model:                 request.Model,
		RequestedScopes:       request.RequestedScopes,
		ScopeUnrestricted:     request.ScopeUnrestricted,
		ConnectorReadiness:    request.ConnectorReadiness,
		EvalStatusOverrides:   request.EvalStatusOverrides,
		AllowPreview:          request.AllowPreview,
		SelectionReason:       "evidence_packet",
		ProvenanceRequirement: "",
		CoverageContext:       request.CoverageContext,
	})
	agents := selectedSecurityAgentProfiles(request, preflight)
	verifiers := evaluateAgentVerifiers(request, preflight, agents)

	return AgentDecisionGuardrails{
		Version:            ContractVersion,
		Preflight:          preflight,
		VerifierResults:    verifiers,
		ActionLadder:       actionStageStatuses(request, verifiers),
		ConnectorToolGates: decideConnectorToolGates(preflight),
		Readiness:          agentReadinessAssessment(preflight, verifiers),
		RequiredWriteBack:  evidencePacketWriteBack(preflight),
	}
}

func agentReadinessAssessment(preflight AgentRunPreflight, verifiers []AgentVerifierResult) AgentReadinessAssessment {
	state := AgentReadinessReady
	reasons := []string{"guardrails_passed"}

	if !preflight.Enabled || verifierStatusCount(verifiers, "blocked") > 0 {
		state = AgentReadinessBlocked
		reasons = []string{"guardrails_blocked"}
	} else if verifierStatusCount(verifiers, "warning") > 0 {
		state = AgentReadinessReadyWithWarnings
		reasons = []string{"guardrail_warnings"}
	}

	return AgentReadinessAssessment{State: state, Reasons: reasons}
}
