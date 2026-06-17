package agentplatform

type AgentPlatformEvalCase struct {
	ID          string                       `json:"id"`
	ScenarioID  string                       `json:"scenario_id"`
	Description string                       `json:"description,omitempty"`
	Expect      AgentPlatformEvalExpectation `json:"expect"`
}

type AgentPlatformEvalExpectation struct {
	RequiredCapabilityIDs          []string `json:"required_capability_ids,omitempty"`
	RequiredContractPaths          []string `json:"required_contract_paths,omitempty"`
	RequiredA2AMethods             []string `json:"required_a2a_methods,omitempty"`
	RequiredA2AUnsupportedMethods  []string `json:"required_a2a_unsupported_methods,omitempty"`
	RequiredEventTypes             []string `json:"required_event_types,omitempty"`
	RequiredIdempotencyRoutes      []string `json:"required_idempotency_routes,omitempty"`
	RequiredRuntimeEvents          []string `json:"required_runtime_events,omitempty"`
	RequiredProvenanceSurfaces     []string `json:"required_provenance_surfaces,omitempty"`
	RequiredIntegrationStrategyIDs []string `json:"required_integration_strategy_ids,omitempty"`
}

type AgentPlatformEvalReport struct {
	Version string                    `json:"version"`
	SuiteID string                    `json:"suite_id"`
	Total   int                       `json:"total"`
	Passed  int                       `json:"passed"`
	Failed  int                       `json:"failed"`
	Results []AgentPlatformEvalResult `json:"results"`
}

type AgentPlatformEvalResult struct {
	ID         string   `json:"id"`
	ScenarioID string   `json:"scenario_id"`
	Passed     bool     `json:"passed"`
	Failures   []string `json:"failures,omitempty"`
}

func RunAgentPlatformEvalSuite(cases []AgentPlatformEvalCase) AgentPlatformEvalReport {
	report := AgentPlatformEvalReport{
		Version: ContractVersion,
		SuiteID: agentEvalSuite().ID,
		Total:   len(cases),
		Results: make([]AgentPlatformEvalResult, 0, len(cases)),
	}
	snapshot := Snapshot()
	for _, evalCase := range cases {
		result := evaluateAgentPlatformEvalCase(evalCase, snapshot)
		if result.Passed {
			report.Passed++
		} else {
			report.Failed++
		}
		report.Results = append(report.Results, result)
	}
	return report
}

func evaluateAgentPlatformEvalCase(evalCase AgentPlatformEvalCase, snapshot Contract) AgentPlatformEvalResult {
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
	for _, id := range expect.RequiredCapabilityIDs {
		if !evalSnapshotHasCapability(snapshot, id) {
			failures = append(failures, "missing capability "+id)
		}
	}
	for _, path := range expect.RequiredContractPaths {
		if !evalSnapshotHasContractPath(snapshot, path) {
			failures = append(failures, "missing contract path "+path)
		}
	}
	for _, method := range expect.RequiredA2AMethods {
		if !containsValue(snapshot.A2A.SupportedMethods, method) {
			failures = append(failures, "missing supported A2A method "+method)
		}
	}
	for _, method := range expect.RequiredA2AUnsupportedMethods {
		if !containsValue(snapshot.A2A.UnsupportedMethods, method) {
			failures = append(failures, "missing unsupported A2A method "+method)
		}
	}
	for _, eventType := range expect.RequiredEventTypes {
		if !evalSnapshotHasEventType(snapshot, eventType) {
			failures = append(failures, "missing event subscription type "+eventType)
		}
	}
	for _, route := range expect.RequiredIdempotencyRoutes {
		if !evalSnapshotHasIdempotencyRoute(snapshot, route) {
			failures = append(failures, "missing idempotency route "+route)
		}
	}
	for _, eventName := range expect.RequiredRuntimeEvents {
		if !evalSnapshotHasRuntimeEvent(snapshot, eventName) {
			failures = append(failures, "missing runtime event "+eventName)
		}
	}
	for _, surface := range expect.RequiredProvenanceSurfaces {
		if !evalSnapshotHasProvenanceSurface(snapshot, surface) {
			failures = append(failures, "missing provenance surface "+surface)
		}
	}
	for _, strategyID := range expect.RequiredIntegrationStrategyIDs {
		if !evalSnapshotHasIntegrationStrategy(snapshot, strategyID) {
			failures = append(failures, "missing integration strategy "+strategyID)
		}
	}
	return AgentPlatformEvalResult{
		ID:         evalCase.ID,
		ScenarioID: evalCase.ScenarioID,
		Passed:     len(failures) == 0,
		Failures:   failures,
	}
}

func evalSnapshotHasCapability(snapshot Contract, id string) bool {
	for _, capability := range snapshot.Capabilities {
		if capability.ID == id {
			return true
		}
	}
	return false
}

func evalSnapshotHasContractPath(snapshot Contract, path string) bool {
	if containsValue(snapshot.A2A.DiscoveryPaths, path) || snapshot.A2A.JSONRPCPath == path {
		return true
	}
	return snapshot.EventSubscriptions.Resource == path ||
		EventSubscriptionContractPath == path ||
		IdempotencyContractPath == path
}

func evalSnapshotHasEventType(snapshot Contract, eventType string) bool {
	for _, candidate := range snapshot.EventSubscriptions.EventTypes {
		if candidate.Name == eventType {
			return true
		}
	}
	return false
}

func evalSnapshotHasIdempotencyRoute(snapshot Contract, route string) bool {
	for _, candidate := range snapshot.Idempotency.Routes {
		if candidate.Path == route {
			return true
		}
	}
	return false
}

func evalSnapshotHasRuntimeEvent(snapshot Contract, name string) bool {
	for _, event := range snapshot.RuntimeEvents {
		if event.Name == name {
			return true
		}
	}
	return false
}

func evalSnapshotHasProvenanceSurface(snapshot Contract, surface string) bool {
	for _, requirement := range snapshot.ProvenanceRequirements {
		if requirement.Surface == surface {
			return true
		}
	}
	return false
}

func evalSnapshotHasIntegrationStrategy(snapshot Contract, id string) bool {
	for _, strategy := range snapshot.SecurityControlPlane.IntegrationStrategies {
		if strategy.ID == id {
			return true
		}
	}
	return false
}

func AgentPlatformEvalScenarioIDs(cases []AgentPlatformEvalCase) []string {
	ids := make([]string, 0, len(cases))
	for _, evalCase := range cases {
		ids = append(ids, evalCase.ScenarioID)
	}
	return uniqueSortedStrings(ids)
}

func AgentPlatformEvalStrategyIDs(cases []AgentPlatformEvalCase) []string {
	ids := []string{}
	for _, evalCase := range cases {
		ids = append(ids, evalCase.Expect.RequiredIntegrationStrategyIDs...)
	}
	return uniqueSortedStrings(ids)
}
