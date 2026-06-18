package agentplatform

type SecurityAgentEvalCase struct {
	ID                 string                       `json:"id"`
	ScenarioID         string                       `json:"scenario_id"`
	Description        string                       `json:"description,omitempty"`
	CoveredStrategyIDs []string                     `json:"covered_strategy_ids,omitempty"`
	Request            EvidencePacketRequest        `json:"request"`
	Expect             SecurityAgentEvalExpectation `json:"expect"`
}

type SecurityAgentEvalExpectation struct {
	PreflightEnabled          *bool             `json:"preflight_enabled,omitempty"`
	ConfidenceLevel           string            `json:"confidence_level,omitempty"`
	SimulationAllowed         *bool             `json:"simulation_allowed,omitempty"`
	RequiredAgentIDs          []string          `json:"required_agent_ids,omitempty"`
	RequiredVerifierStatuses  map[string]string `json:"required_verifier_statuses,omitempty"`
	RequiredConnectorStatuses map[string]string `json:"required_connector_statuses,omitempty"`
	RequiredActionStatuses    map[string]string `json:"required_action_statuses,omitempty"`
	RequiredEvalScenarioIDs   []string          `json:"required_eval_scenario_ids,omitempty"`
	RequiredConfidenceReasons []string          `json:"required_confidence_reasons,omitempty"`
	RequiredPreflightBlockers []string          `json:"required_preflight_blockers,omitempty"`
	RequiredEvidenceKinds     []string          `json:"required_evidence_kinds,omitempty"`
	RequiredWriteBack         []string          `json:"required_write_back,omitempty"`
	ForbiddenVerifierStatuses map[string]string `json:"forbidden_verifier_statuses,omitempty"`
}

type SecurityAgentEvalReport struct {
	Version string                    `json:"version"`
	SuiteID string                    `json:"suite_id"`
	Total   int                       `json:"total"`
	Passed  int                       `json:"passed"`
	Failed  int                       `json:"failed"`
	Results []SecurityAgentEvalResult `json:"results"`
}

type SecurityAgentEvalResult struct {
	ID         string                `json:"id"`
	ScenarioID string                `json:"scenario_id"`
	Passed     bool                  `json:"passed"`
	Failures   []string              `json:"failures,omitempty"`
	Confidence AgentPacketConfidence `json:"confidence"`
	Verifier   map[string]string     `json:"verifier"`
	Agents     []string              `json:"agents"`
}

func RunSecurityAgentEvalSuite(cases []SecurityAgentEvalCase) SecurityAgentEvalReport {
	report := SecurityAgentEvalReport{
		Version: ContractVersion,
		SuiteID: agentEvalSuite().ID,
		Total:   len(cases),
		Results: make([]SecurityAgentEvalResult, 0, len(cases)),
	}
	for _, evalCase := range cases {
		packet := BuildEvidencePacket(evalCase.Request)
		result := evaluateSecurityAgentEvalCase(evalCase, packet)
		if result.Passed {
			report.Passed++
		} else {
			report.Failed++
		}
		report.Results = append(report.Results, result)
	}
	return report
}

func evaluateSecurityAgentEvalCase(evalCase SecurityAgentEvalCase, packet AgentEvidencePacket) SecurityAgentEvalResult {
	failures := []string{}
	expect := evalCase.Expect
	if evalCase.ID == "" {
		failures = append(failures, "missing eval case id")
	}
	if evalCase.ScenarioID == "" {
		failures = append(failures, "missing scenario id")
	} else if !knownAgentEvalScenario(evalCase.ScenarioID) {
		failures = append(failures, "unknown scenario id "+evalCase.ScenarioID)
	}
	if expect.PreflightEnabled != nil && packet.Preflight.Enabled != *expect.PreflightEnabled {
		failures = append(failures, "preflight enabled mismatch")
	}
	if expect.ConfidenceLevel != "" && packet.Confidence.Level != expect.ConfidenceLevel {
		failures = append(failures, "confidence level = "+packet.Confidence.Level+", want "+expect.ConfidenceLevel)
	}
	if expect.SimulationAllowed != nil && packet.SimulationPlan.Allowed != *expect.SimulationAllowed {
		failures = append(failures, "simulation allowed mismatch")
	}
	for _, id := range expect.RequiredAgentIDs {
		if !evalPacketHasAgent(packet, id) {
			failures = append(failures, "missing agent "+id)
		}
	}
	for id, status := range expect.RequiredVerifierStatuses {
		if evalPacketVerifierStatus(packet, id) != status {
			failures = append(failures, "verifier "+id+" status mismatch")
		}
	}
	for id, status := range expect.ForbiddenVerifierStatuses {
		if evalPacketVerifierStatus(packet, id) == status {
			failures = append(failures, "verifier "+id+" had forbidden status "+status)
		}
	}
	for id, status := range expect.RequiredConnectorStatuses {
		if evalPacketConnectorStatus(packet, id) != status {
			failures = append(failures, "connector gate "+id+" status mismatch")
		}
	}
	for id, status := range expect.RequiredActionStatuses {
		if evalPacketActionStatus(packet, id) != status {
			failures = append(failures, "action stage "+id+" status mismatch")
		}
	}
	for _, id := range expect.RequiredEvalScenarioIDs {
		if !evalPacketHasEvalScenario(packet, id) {
			failures = append(failures, "missing eval scenario "+id)
		}
	}
	for _, reason := range expect.RequiredConfidenceReasons {
		if !containsValue(packet.Confidence.Reasons, reason) {
			failures = append(failures, "missing confidence reason "+reason)
		}
	}
	for _, code := range expect.RequiredPreflightBlockers {
		if !evalPacketHasPreflightBlocker(packet, code) {
			failures = append(failures, "missing preflight blocker "+code)
		}
	}
	for _, kind := range expect.RequiredEvidenceKinds {
		if !evalPacketHasEvidenceKind(packet, kind) {
			failures = append(failures, "missing evidence kind "+kind)
		}
	}
	for _, writeBack := range expect.RequiredWriteBack {
		if !containsValue(packet.RequiredWriteBack, writeBack) {
			failures = append(failures, "missing write-back "+writeBack)
		}
	}
	return SecurityAgentEvalResult{
		ID:         evalCase.ID,
		ScenarioID: evalCase.ScenarioID,
		Passed:     len(failures) == 0,
		Failures:   failures,
		Confidence: packet.Confidence,
		Verifier:   evalPacketVerifierStatuses(packet),
		Agents:     evalPacketAgentIDs(packet),
	}
}

func knownAgentEvalScenario(id string) bool {
	for _, scenario := range agentEvalSuite().Scenarios {
		if scenario.ID == id {
			return true
		}
	}
	return false
}

func evalPacketAgentIDs(packet AgentEvidencePacket) []string {
	ids := make([]string, 0, len(packet.RecommendedAgents))
	for _, agent := range packet.RecommendedAgents {
		ids = append(ids, agent.ID)
	}
	return uniqueSortedStrings(ids)
}

func evalPacketHasAgent(packet AgentEvidencePacket, id string) bool {
	return containsValue(evalPacketAgentIDs(packet), id)
}

func evalPacketVerifierStatuses(packet AgentEvidencePacket) map[string]string {
	statuses := map[string]string{}
	for _, result := range packet.VerifierResults {
		statuses[result.ID] = result.Status
	}
	return statuses
}

func evalPacketVerifierStatus(packet AgentEvidencePacket, id string) string {
	return evalPacketVerifierStatuses(packet)[id]
}

func evalPacketConnectorStatus(packet AgentEvidencePacket, id string) string {
	for _, gate := range packet.ConnectorToolGates {
		if gate.GateID == id {
			return gate.Status
		}
	}
	return ""
}

func evalPacketActionStatus(packet AgentEvidencePacket, id string) string {
	for _, status := range packet.ActionLadder {
		if status.Stage.ID == id {
			return status.Status
		}
	}
	return ""
}

func evalPacketHasEvalScenario(packet AgentEvidencePacket, id string) bool {
	for _, scenario := range packet.EvalChecklist {
		if scenario.ID == id {
			return true
		}
	}
	return false
}

func evalPacketHasPreflightBlocker(packet AgentEvidencePacket, code string) bool {
	for _, blocker := range packet.Preflight.Blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}

func evalPacketHasEvidenceKind(packet AgentEvidencePacket, kind string) bool {
	for _, ref := range packet.EvidenceRefs {
		if ref.Kind == kind {
			return true
		}
	}
	return false
}

func SecurityAgentEvalScenarioIDs(cases []SecurityAgentEvalCase) []string {
	ids := make([]string, 0, len(cases))
	for _, evalCase := range cases {
		ids = append(ids, evalCase.ScenarioID)
	}
	return uniqueSortedStrings(ids)
}

func SecurityAgentEvalStrategyIDs(cases []SecurityAgentEvalCase) []string {
	ids := []string{}
	for _, evalCase := range cases {
		ids = append(ids, evalCase.CoveredStrategyIDs...)
	}
	return uniqueSortedStrings(ids)
}
