package agentplatform

import "testing"

func TestSecurityControlPlaneSnapshotCoversAgentStrategies(t *testing.T) {
	snapshot := SecurityControlPlaneSnapshot()
	if snapshot.Version != ContractVersion {
		t.Fatalf("version = %q, want %q", snapshot.Version, ContractVersion)
	}
	for _, required := range []string{
		"preflight",
		"evidence_refs",
		"recommended_agents",
		"verifier_results",
		"action_ladder",
		"eval_checklist",
		"security_memory",
		"connector_tool_gates",
		"simulation_plan",
		"confidence",
	} {
		if !containsString(snapshot.EvidencePacket.RequiredBlocks, required) {
			t.Fatalf("evidence packet contract missing required block %q: %+v", required, snapshot.EvidencePacket.RequiredBlocks)
		}
	}

	strategies := map[string]bool{}
	for _, strategy := range snapshot.IntegrationStrategies {
		strategies[strategy.ID] = true
		if strategy.Purpose == "" || len(strategy.Benefits) == 0 || len(strategy.Controls) == 0 {
			t.Fatalf("strategy must explain purpose, benefits, and controls: %+v", strategy)
		}
	}
	for _, required := range []string{
		"agent-evidence-packets",
		"verifier-layer",
		"specialized-agents",
		"action-ladder",
		"cerebro-agent-platform-eval",
		"graph-ask-regression-evals",
		"model-provider-comparison",
		"ai-provider-governance",
		"a2a-protocol-boundary",
		"event-subscription-webhooks",
		"public-idempotency-contract",
		"security-memory",
		"connector-oauth-agent-infra",
		"defensive-simulation-harness",
	} {
		if !strategies[required] {
			t.Fatalf("integration strategy %q missing: %+v", required, snapshot.IntegrationStrategies)
		}
	}

	profiles := map[string]SecurityAgentProfile{}
	for _, profile := range snapshot.AgentProfiles {
		profiles[profile.ID] = profile
		if len(profile.CapabilityIDs) == 0 || len(profile.RequiredVerifiers) == 0 || profile.MaxActionStage == "" {
			t.Fatalf("profile must expose capability, verifier, and action bounds: %+v", profile)
		}
	}
	for _, required := range []string{"coverage-scout", "remediation-planner", "detection-engineer", "ai-governance-analyst"} {
		if _, ok := profiles[required]; !ok {
			t.Fatalf("profile %q missing: %+v", required, snapshot.AgentProfiles)
		}
	}

	expectedStages := []string{
		ActionStageObserve,
		ActionStageExplain,
		ActionStageRecommend,
		ActionStageDryRun,
		ActionStageApprove,
		ActionStageExecute,
		ActionStageVerify,
		ActionStageCloseLoop,
	}
	if len(snapshot.ActionLadder) != len(expectedStages) {
		t.Fatalf("action ladder length = %d, want %d", len(snapshot.ActionLadder), len(expectedStages))
	}
	for i, expected := range expectedStages {
		stage := snapshot.ActionLadder[i]
		if stage.ID != expected || stage.Order != i+1 {
			t.Fatalf("stage[%d] = %+v, want id %q order %d", i, stage, expected, i+1)
		}
		if stage.ID == ActionStageExecute && (!stage.Mutating || !stage.RequiresApproval) {
			t.Fatalf("execute stage must require approval and be marked mutating: %+v", stage)
		}
	}

	scenarios := map[string]bool{}
	for _, scenario := range snapshot.EvalSuite.Scenarios {
		scenarios[scenario.ID] = true
		if scenario.Capability == "" || len(scenario.Rubrics) == 0 {
			t.Fatalf("eval scenario must bind capability and rubrics: %+v", scenario)
		}
	}
	for _, required := range []string{"tenant-isolation", "graph-ask-grounded-regression", "model-provider-comparison", "graph-action-execution-safety", "ai-governance-posture", "simulation-bounds"} {
		if !scenarios[required] {
			t.Fatalf("eval scenario %q missing: %+v", required, snapshot.EvalSuite.Scenarios)
		}
	}
	for _, required := range []string{"tenant_id", "source_urn", "citation_status"} {
		if !containsString(snapshot.SecurityMemory.RequiredFields, required) {
			t.Fatalf("security memory missing required field %q: %+v", required, snapshot.SecurityMemory.RequiredFields)
		}
	}
	if snapshot.SimulationHarness.Mode != "graph_or_fixture_only" {
		t.Fatalf("simulation mode = %q, want graph_or_fixture_only", snapshot.SimulationHarness.Mode)
	}
	if len(snapshot.RubricVerifiers) == 0 || len(snapshot.ModelComparisons) == 0 || len(snapshot.AIGovernanceSources) == 0 {
		t.Fatalf("snapshot missing NLP governance surfaces: rubrics=%+v comparisons=%+v sources=%+v", snapshot.RubricVerifiers, snapshot.ModelComparisons, snapshot.AIGovernanceSources)
	}
}

func TestSecurityControlPlaneReferencesKnownRegistryEntries(t *testing.T) {
	snapshot := SecurityControlPlaneSnapshot()
	verifiers := map[string]bool{}
	for _, verifier := range snapshot.VerifierLayer {
		verifiers[verifier.ID] = true
		if _, ok := DomainByID(verifier.OwnerDomain); !ok {
			t.Fatalf("verifier %q references unknown owner domain %q", verifier.ID, verifier.OwnerDomain)
		}
	}
	runtimeEvents := runtimeEventNames()
	for _, profile := range snapshot.AgentProfiles {
		for _, capabilityID := range profile.CapabilityIDs {
			if _, ok := capabilityByID(capabilityID); !ok {
				t.Fatalf("profile %q references unknown capability %q", profile.ID, capabilityID)
			}
		}
		for _, verifierID := range profile.RequiredVerifiers {
			if !verifiers[verifierID] {
				t.Fatalf("profile %q references unknown verifier %q", profile.ID, verifierID)
			}
		}
		if actionStageOrder(profile.MaxActionStage) == 0 {
			t.Fatalf("profile %q references unknown max action stage %q", profile.ID, profile.MaxActionStage)
		}
	}

	stageOrders := map[int]string{}
	stageIDs := map[string]bool{}
	for _, stage := range snapshot.ActionLadder {
		if prior := stageOrders[stage.Order]; prior != "" {
			t.Fatalf("action stage order %d used by %q and %q", stage.Order, prior, stage.ID)
		}
		stageOrders[stage.Order] = stage.ID
		stageIDs[stage.ID] = true
		for _, event := range stage.RequiredEvents {
			if !runtimeEvents[event] {
				t.Fatalf("action stage %q references unknown runtime event %q", stage.ID, event)
			}
		}
		for _, verifierID := range stage.VerifierIDs {
			if !verifiers[verifierID] {
				t.Fatalf("action stage %q references unknown verifier %q", stage.ID, verifierID)
			}
		}
	}
	for _, gate := range snapshot.ConnectorToolGates {
		if !runtimeEvents[gate.RuntimeEvent] {
			t.Fatalf("connector gate %q references unknown runtime event %q", gate.ID, gate.RuntimeEvent)
		}
	}
	for _, verifierID := range snapshot.SimulationHarness.VerifierIDs {
		if !verifiers[verifierID] {
			t.Fatalf("simulation harness references unknown verifier %q", verifierID)
		}
	}
	for _, scenario := range snapshot.EvalSuite.Scenarios {
		if _, ok := capabilityByID(scenario.Capability); !ok {
			t.Fatalf("eval scenario %q references unknown capability %q", scenario.ID, scenario.Capability)
		}
	}
	scenarioIDs := map[string]bool{}
	for _, scenario := range snapshot.EvalSuite.Scenarios {
		scenarioIDs[scenario.ID] = true
	}
	for _, rubric := range snapshot.RubricVerifiers {
		if _, ok := capabilityByID(rubric.CapabilityID); !ok {
			t.Fatalf("rubric verifier %q references unknown capability %q", rubric.ID, rubric.CapabilityID)
		}
		if len(rubric.RequiredSignals) == 0 {
			t.Fatalf("rubric verifier %q must declare required signals", rubric.ID)
		}
	}
	for _, comparison := range snapshot.ModelComparisons {
		if _, ok := capabilityByID(comparison.CapabilityID); !ok {
			t.Fatalf("model comparison %q references unknown capability %q", comparison.ID, comparison.CapabilityID)
		}
		for _, scenarioID := range comparison.ScenarioIDs {
			if !scenarioIDs[scenarioID] {
				t.Fatalf("model comparison %q references unknown scenario %q", comparison.ID, scenarioID)
			}
		}
		if len(comparison.ModelRoutes) == 0 || len(comparison.RequiredMetrics) == 0 || comparison.PromotionGate == "" {
			t.Fatalf("model comparison %q must declare routes, metrics, and promotion gate", comparison.ID)
		}
	}
	for _, source := range snapshot.AIGovernanceSources {
		if source.SourceID == "" || len(source.GovernedFamilies) == 0 || len(source.RiskSignals) == 0 {
			t.Fatalf("AI governance source must declare source, families, and risk signals: %+v", source)
		}
		if _, ok := capabilityByID(source.RecommendedCapability); !ok {
			t.Fatalf("AI governance source %q references unknown capability %q", source.SourceID, source.RecommendedCapability)
		}
	}
	readableMemoryTypes := map[string]bool{}
	for _, memoryType := range snapshot.SecurityMemory.ReadableTypes {
		readableMemoryTypes[memoryType.ID] = true
		if memoryType.TTL == "" || len(memoryType.Surfaces) == 0 {
			t.Fatalf("readable memory type must declare TTL and surfaces: %+v", memoryType)
		}
	}
	for _, memoryType := range snapshot.SecurityMemory.WritableTypes {
		if !readableMemoryTypes[memoryType.ID] {
			t.Fatalf("writable memory type %q is not readable", memoryType.ID)
		}
	}
	for _, required := range []string{ActionStageObserve, ActionStageRecommend, ActionStageExecute, ActionStageCloseLoop} {
		if !stageIDs[required] {
			t.Fatalf("action ladder missing required stage %q", required)
		}
	}
}

func TestBuildEvidencePacketWarnsOnCoverageAndBlocksUnapprovedExecution(t *testing.T) {
	packet := BuildEvidencePacket(EvidencePacketRequest{
		TenantID:        "tenant-1",
		ActorID:         "analyst-1",
		Question:        "Fix externally reachable exposure",
		ScopeURN:        "urn:cerebro:tenant-1:asset:prod-app",
		CapabilityIDs:   []string{"graph-reasoning", "runtime-response-actions"},
		RequestedScopes: []string{ScopeCosmoSecurityRead, ScopeRuntimeResponseWrite},
		AllowPreview:    true,
		Action: EvidencePacketAction{
			Stage:      ActionStageExecute,
			TargetURNs: []string{"urn:cerebro:tenant-1:asset:prod-app"},
		},
		CoverageContext: &AgentCoverageContext{
			Version:        ContractVersion,
			TenantID:       "tenant-1",
			BlindSpotCount: 1,
			TopBlindSpots: []AgentCoverageBlindSpot{{
				SourceID:    "okta",
				DimensionID: "applications",
				Title:       "Application inventory",
			}},
		},
	})

	if packet.Confidence.Level != "blocked" {
		t.Fatalf("confidence = %+v, want blocked", packet.Confidence)
	}
	if !packetHasVerifierStatus(packet, "coverage-blind-spots", "warning") {
		t.Fatalf("packet missing coverage warning: %+v", packet.VerifierResults)
	}
	if !packetHasVerifierStatus(packet, "action-ladder", "blocked") || !packetHasVerifierStatus(packet, "remediation-safety", "blocked") {
		t.Fatalf("packet missing action blockers: %+v", packet.VerifierResults)
	}
	if packet.SimulationPlan.Allowed {
		t.Fatalf("simulation plan allowed = true, want blocked: %+v", packet.SimulationPlan)
	}
	if !packetHasRecommendedAgent(packet, "coverage-scout") || !packetHasRecommendedAgent(packet, "remediation-planner") {
		t.Fatalf("recommended agents = %+v, want coverage scout and remediation planner", packet.RecommendedAgents)
	}
	if len(packet.RequiredWriteBack) == 0 || !containsString(packet.RequiredWriteBack, "verifier_results") {
		t.Fatalf("required write-back = %+v, want verifier results", packet.RequiredWriteBack)
	}
}

func TestBuildEvidencePacketBlocksUnapprovedGraphActionExecution(t *testing.T) {
	packet := BuildEvidencePacket(EvidencePacketRequest{
		TenantID:        "tenant-1",
		ActorID:         "analyst-1",
		Question:        "Remediate this Okta identity drift by sending the user to Okta jail.",
		ScopeURN:        "urn:cerebro:tenant-1:finding:identity-drift-1",
		CapabilityIDs:   []string{"graph-reasoning", "graph-action-execution"},
		RequestedScopes: []string{ScopeCosmoSecurityRead, ScopeGraphActionsWrite},
		AllowPreview:    true,
		Action: EvidencePacketAction{
			Stage:      ActionStageExecute,
			TargetURNs: []string{"urn:cerebro:tenant-1:okta.user:00u123"},
		},
		CoverageContext: &AgentCoverageContext{
			Version:         ContractVersion,
			TenantID:        "tenant-1",
			SourceID:        "okta",
			TotalDimensions: 3,
		},
	})

	if !packet.Preflight.Enabled {
		t.Fatalf("preflight enabled = false, blockers = %+v", packet.Preflight.Blockers)
	}
	if !containsString(packet.Preflight.SelectedCapabilities, "graph-action-execution") {
		t.Fatalf("selected capabilities = %+v, want graph-action-execution", packet.Preflight.SelectedCapabilities)
	}
	if packet.Confidence.Level != "blocked" {
		t.Fatalf("confidence = %+v, want blocked until approval", packet.Confidence)
	}
	if !packetHasVerifierStatus(packet, "action-ladder", "blocked") || !packetHasVerifierStatus(packet, "remediation-safety", "blocked") {
		t.Fatalf("packet missing action blockers: %+v", packet.VerifierResults)
	}
	if !packetHasEvalScenario(packet, "graph-action-execution-safety") {
		t.Fatalf("packet eval checklist missing graph action scenario: %+v", packet.EvalChecklist)
	}
	if !packetHasRecommendedAgent(packet, "remediation-planner") {
		t.Fatalf("recommended agents = %+v, want remediation planner", packet.RecommendedAgents)
	}
}

func TestBuildEvidencePacketSelectsAIGovernanceAnalyst(t *testing.T) {
	packet := BuildEvidencePacket(EvidencePacketRequest{
		TenantID:        "tenant-1",
		ActorID:         "analyst-1",
		Question:        "Review OpenAI hosted tool permissions and model usage.",
		ScopeURN:        "urn:cerebro:tenant-1:source:openai",
		CapabilityIDs:   []string{"ai-provider-governance", "knowledge-provenance"},
		RequestedScopes: []string{ScopeCosmoSecurityRead},
		Action:          EvidencePacketAction{Stage: ActionStageRecommend},
		CoverageContext: &AgentCoverageContext{
			Version:         ContractVersion,
			TenantID:        "tenant-1",
			SourceID:        "openai",
			TotalDimensions: 4,
		},
	})

	if !packetHasRecommendedAgent(packet, "ai-governance-analyst") {
		t.Fatalf("packet agents = %+v, want ai-governance-analyst", packet.RecommendedAgents)
	}
	if !packetHasVerifierStatus(packet, "ai-provider-governance", "pass") {
		t.Fatalf("packet missing AI provider governance pass: %+v", packet.VerifierResults)
	}
	if !packetHasEvalScenario(packet, "ai-governance-posture") {
		t.Fatalf("packet eval checklist missing ai-governance-posture: %+v", packet.EvalChecklist)
	}
}

func TestBuildEvidencePacketSelectsAIGovernanceAnalystWhenAccessIsMentioned(t *testing.T) {
	packet := BuildEvidencePacket(EvidencePacketRequest{
		TenantID:        "tenant-1",
		ActorID:         "analyst-1",
		Question:        "Review OpenAI model access and hosted tool permissions.",
		ScopeURN:        "urn:cerebro:tenant-1:source:openai",
		CapabilityIDs:   []string{"ai-provider-governance", "knowledge-provenance"},
		RequestedScopes: []string{ScopeCosmoSecurityRead},
		Action:          EvidencePacketAction{Stage: ActionStageRecommend},
		CoverageContext: &AgentCoverageContext{
			Version:         ContractVersion,
			TenantID:        "tenant-1",
			SourceID:        "openai",
			TotalDimensions: 4,
		},
	})

	if !packetHasRecommendedAgent(packet, "ai-governance-analyst") {
		t.Fatalf("packet agents = %+v, want ai-governance-analyst", packet.RecommendedAgents)
	}
	if !packetHasRecommendedAgent(packet, "identity-drift-analyst") {
		t.Fatalf("packet agents = %+v, want identity-drift-analyst for access review", packet.RecommendedAgents)
	}
	if !packetHasVerifierStatus(packet, "ai-provider-governance", "pass") {
		t.Fatalf("packet missing AI provider governance pass: %+v", packet.VerifierResults)
	}
}

func TestAgentModelComparisonsUseStableRouteIDs(t *testing.T) {
	snapshot := SecurityControlPlaneSnapshot()
	for _, comparison := range snapshot.ModelComparisons {
		if comparison.ID != "graph-ask-model-routes" {
			continue
		}
		for _, required := range []string{"claude-sonnet-4-6", "claude-opus-4-7", "claude-haiku-4-5"} {
			if !containsString(comparison.ModelRoutes, required) {
				t.Fatalf("model routes = %+v, want %q", comparison.ModelRoutes, required)
			}
		}
		if containsString(comparison.ModelRoutes, "claude-haiku-4-5-20251001") {
			t.Fatalf("model routes = %+v, want route IDs without date suffixes", comparison.ModelRoutes)
		}
		return
	}
	t.Fatal("graph-ask-model-routes comparison missing")
}

func TestBuildEvidencePacketKeepsBlockedConfidenceWithoutCoverage(t *testing.T) {
	packet := BuildEvidencePacket(EvidencePacketRequest{
		TenantID:        "tenant-1",
		ActorID:         "analyst-1",
		Question:        "Fix this issue",
		ScopeURN:        "urn:cerebro:tenant-1:asset:prod-app",
		CapabilityIDs:   []string{"graph-reasoning", "runtime-response-actions"},
		RequestedScopes: []string{ScopeCosmoSecurityRead, ScopeRuntimeResponseWrite},
		AllowPreview:    true,
		Action: EvidencePacketAction{
			Stage:      ActionStageExecute,
			TargetURNs: []string{"urn:cerebro:tenant-1:asset:prod-app"},
		},
	})

	if !packetHasVerifierStatus(packet, "action-ladder", "blocked") || !packetHasVerifierStatus(packet, "remediation-safety", "blocked") {
		t.Fatalf("packet missing action blockers: %+v", packet.VerifierResults)
	}
	if packet.Confidence.Level != "blocked" {
		t.Fatalf("confidence = %+v, want blocked even when coverage is unavailable", packet.Confidence)
	}
	if !containsString(packet.Confidence.Reasons, "coverage_unavailable") {
		t.Fatalf("confidence reasons = %+v, want coverage_unavailable", packet.Confidence.Reasons)
	}
}

func TestBuildEvidencePacketBlocksCrossTenantContextURN(t *testing.T) {
	packet := BuildEvidencePacket(EvidencePacketRequest{
		TenantID:        "tenant-1",
		ActorID:         "analyst-1",
		Question:        "Triage this alert",
		ScopeURN:        "urn:cerebro:tenant-1:finding:alert-1",
		EvidenceURNs:    []string{"urn:cerebro:other:finding:alert-2"},
		CapabilityIDs:   []string{"graph-reasoning"},
		RequestedScopes: []string{"cosmo.security.read"},
		Action: EvidencePacketAction{
			Stage:      ActionStageRecommend,
			TargetURNs: []string{"urn:cerebro:tenant-1:finding:alert-1"},
		},
		MemoryHints: []SecurityMemoryHint{{
			Type: "prior_investigation",
			URN:  "urn:cerebro:tenant-1:investigation:prev",
		}},
	})

	if !packetHasVerifierStatus(packet, "tenant-scope", "blocked") {
		t.Fatalf("packet missing tenant-scope blocker: %+v", packet.VerifierResults)
	}
	if packet.Confidence.Level != "blocked" {
		t.Fatalf("confidence = %+v, want blocked", packet.Confidence)
	}
}

func TestBuildEvidencePacketAllowsGraphOnlySimulationForScopedRecommendation(t *testing.T) {
	packet := BuildEvidencePacket(EvidencePacketRequest{
		TenantID:        "tenant-1",
		ActorID:         "analyst-1",
		Question:        "Triage this alert",
		ScopeURN:        "urn:cerebro:tenant-1:finding:alert-1",
		CapabilityIDs:   []string{"graph-reasoning"},
		RequestedScopes: []string{"cosmo.security.read"},
		Action: EvidencePacketAction{
			Stage: ActionStageRecommend,
		},
		CoverageContext: &AgentCoverageContext{
			Version:     ContractVersion,
			TenantID:    "tenant-1",
			SourceID:    "okta",
			GeneratedAt: "2026-06-16T00:00:00Z",
		},
		MemoryHints: []SecurityMemoryHint{{
			Type: "prior_investigation",
			URN:  "urn:cerebro:tenant-1:investigation:prev",
		}},
	})

	if packet.Confidence.Level != "high" {
		t.Fatalf("confidence = %+v, want high", packet.Confidence)
	}
	if packetHasAnyVerifierStatus(packet, "blocked") {
		t.Fatalf("packet has blocked verifiers: %+v", packet.VerifierResults)
	}
	if !packet.SimulationPlan.Allowed || packet.SimulationPlan.Mode != "graph_or_fixture_only" {
		t.Fatalf("simulation plan = %+v, want allowed graph-only mode", packet.SimulationPlan)
	}
	if len(packet.EvalChecklist) == 0 {
		t.Fatal("packet missing eval checklist")
	}
	if status := packetActionStageStatus(packet, ActionStageRecommend); status != "requested" {
		t.Fatalf("recommend stage status = %q, want requested", status)
	}
	if len(packet.SecurityMemory.ReadableTypes) == 0 || len(packet.SecurityMemory.Hints) != 1 {
		t.Fatalf("security memory plan = %+v, want readable types and one hint", packet.SecurityMemory)
	}
}

func packetHasRecommendedAgent(packet AgentEvidencePacket, id string) bool {
	for _, agent := range packet.RecommendedAgents {
		if agent.ID == id {
			return true
		}
	}
	return false
}

func packetHasVerifierStatus(packet AgentEvidencePacket, id string, status string) bool {
	for _, result := range packet.VerifierResults {
		if result.ID == id && result.Status == status {
			return true
		}
	}
	return false
}

func packetHasAnyVerifierStatus(packet AgentEvidencePacket, status string) bool {
	for _, result := range packet.VerifierResults {
		if result.Status == status {
			return true
		}
	}
	return false
}

func packetHasEvalScenario(packet AgentEvidencePacket, id string) bool {
	for _, scenario := range packet.EvalChecklist {
		if scenario.ID == id {
			return true
		}
	}
	return false
}

func packetActionStageStatus(packet AgentEvidencePacket, stageID string) string {
	for _, status := range packet.ActionLadder {
		if status.Stage.ID == stageID {
			return status.Status
		}
	}
	return ""
}
