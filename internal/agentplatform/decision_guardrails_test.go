package agentplatform

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestBuildAgentDecisionGuardrailsReadiness(t *testing.T) {
	tests := []struct {
		name string
		req  EvidencePacketRequest
		want string
	}{
		{
			name: "ready",
			req: EvidencePacketRequest{
				TenantID:        "tenant-1",
				ActorID:         "analyst-1",
				Question:        "Review this finding",
				ScopeURN:        "urn:cerebro:tenant-1:finding:finding-1",
				CapabilityIDs:   []string{"graph-reasoning"},
				RequestedScopes: []string{ScopeCosmoSecurityRead},
				Action:          EvidencePacketAction{Stage: ActionStageRecommend},
				CoverageContext: &AgentCoverageContext{Version: ContractVersion, TenantID: "tenant-1"},
			},
			want: AgentReadinessReady,
		},
		{
			name: "ready with warnings",
			req: EvidencePacketRequest{
				TenantID:        "tenant-1",
				ActorID:         "analyst-1",
				Question:        "Review this finding",
				ScopeURN:        "urn:cerebro:tenant-1:finding:finding-1",
				CapabilityIDs:   []string{"graph-reasoning"},
				RequestedScopes: []string{ScopeCosmoSecurityRead},
				Action:          EvidencePacketAction{Stage: ActionStageRecommend},
				CoverageContext: &AgentCoverageContext{Version: ContractVersion, TenantID: "tenant-1", BlindSpotCount: 1},
			},
			want: AgentReadinessReadyWithWarnings,
		},
		{
			name: "blocked",
			req: EvidencePacketRequest{
				TenantID:        "tenant-1",
				ActorID:         "analyst-1",
				Question:        "Execute this action",
				ScopeURN:        "urn:cerebro:tenant-1:finding:finding-1",
				CapabilityIDs:   []string{"graph-reasoning", "runtime-response-actions"},
				RequestedScopes: []string{ScopeCosmoSecurityRead, ScopeRuntimeResponseWrite},
				AllowPreview:    true,
				Action:          EvidencePacketAction{Stage: ActionStageExecute},
			},
			want: AgentReadinessBlocked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildAgentDecisionGuardrails(tt.req)
			if got.Readiness.State != tt.want {
				t.Fatalf("readiness = %+v, want %q", got.Readiness, tt.want)
			}
			if len(got.Readiness.Reasons) == 0 {
				t.Fatal("readiness reasons are empty")
			}
		})
	}
}

func TestBuildEvidencePacketCanonicalJSONCompatibility(t *testing.T) {
	request := EvidencePacketRequest{
		TenantID:        " tenant-1 ",
		ActorID:         " analyst-1 ",
		Question:        " Review this finding ",
		ScopeURN:        " urn:cerebro:tenant-1:finding:finding-1 ",
		CapabilityIDs:   []string{"knowledge-provenance", "graph-reasoning", "graph-reasoning"},
		RequestedScopes: []string{ScopeCosmoSecurityRead},
		EvidenceURNs:    []string{"urn:cerebro:tenant-1:evidence:evidence-1"},
		GeneratedAt:     "2026-07-15T08:00:00Z",
		Action:          EvidencePacketAction{Stage: ActionStageRecommend},
		CoverageContext: &AgentCoverageContext{Version: ContractVersion, TenantID: "tenant-1"},
	}

	want := buildLegacyEvidencePacketForTest(request)
	got := BuildEvidencePacket(request)
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal legacy packet: %v", err)
	}
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal adapted packet: %v", err)
	}
	if !reflect.DeepEqual(gotJSON, wantJSON) {
		t.Fatalf("canonical JSON changed\n got: %s\nwant: %s", gotJSON, wantJSON)
	}
}

// buildLegacyEvidencePacketForTest preserves the pre-extraction assembly so
// the compatibility test detects any change in the existing response.
func buildLegacyEvidencePacketForTest(request EvidencePacketRequest) AgentEvidencePacket {
	request = normalizeEvidencePacketRequest(request)
	preflight := PreflightAgentRun(AgentRunPreflightRequest{
		TenantID: request.TenantID, ActorID: request.ActorID, CapabilityIDs: request.CapabilityIDs,
		Question: request.Question, ScopeURN: request.ScopeURN, Model: request.Model,
		RequestedScopes: request.RequestedScopes, ScopeUnrestricted: request.ScopeUnrestricted,
		ConnectorReadiness: request.ConnectorReadiness, EvalStatusOverrides: request.EvalStatusOverrides,
		AllowPreview: request.AllowPreview, SelectionReason: "evidence_packet",
		CoverageContext: request.CoverageContext,
	})
	agents := selectedSecurityAgentProfiles(request, preflight)
	verifiers := evaluateAgentVerifiers(request, preflight, agents)
	packet := AgentEvidencePacket{
		Version: ContractVersion, TenantID: request.TenantID, ActorID: request.ActorID,
		Question: request.Question, ScopeURN: request.ScopeURN,
		GeneratedAt: evidencePacketGeneratedAt(request.GeneratedAt), Preflight: preflight,
		EvidenceRefs: evidenceReferences(request, preflight), RecommendedAgents: agents,
		VerifierResults: verifiers, ActionLadder: actionStageStatuses(request, verifiers),
		EvalChecklist: evalChecklistForAgents(agents), SecurityMemory: securityMemoryPlan(request),
		ConnectorToolGates: decideConnectorToolGates(preflight),
		SimulationPlan:     defensiveSimulationPlan(request, verifiers),
		RequiredWriteBack:  evidencePacketWriteBack(preflight),
	}
	packet.Confidence = evidencePacketConfidence(packet)
	return packet
}
