package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/graph"
	risk "github.com/writer/cerebro/internal/graph/risk"
)

type stubGraphRiskService struct {
	stats          *graphRiskStatsResponse
	blast          *risk.BlastRadiusResult
	cascading      *risk.CascadingBlastRadiusResult
	reverse        *risk.ReverseAccessResult
	rebuild        *graphRebuildResponse
	report         *risk.SecurityReport
	apiSurface     *graph.APISurfaceReport
	toxic          []*risk.ToxicCombination
	attackPaths    *risk.SimulationResult
	fix            *risk.FixSimulation
	chokepoints    []*risk.Chokepoint
	escalation     []*graph.PrivilegeEscalationRisk
	peerAnalysis   *graph.PeerGroupAnalysis
	privilegeCreep []*graph.OutlierNode
	permissions    *graph.EffectivePermissions
	accessCompare  *graph.AccessComparison
	vendorReport   *graph.VendorRiskReport
	vendorCapture  func(graph.VendorRiskReportOptions)
}

func (s stubGraphRiskService) GraphStats(context.Context) (*graphRiskStatsResponse, error) {
	if s.stats == nil {
		return &graphRiskStatsResponse{}, nil
	}
	return s.stats, nil
}

func (s stubGraphRiskService) BlastRadius(context.Context, string, int) (*risk.BlastRadiusResult, error) {
	if s.blast == nil {
		return &risk.BlastRadiusResult{}, nil
	}
	return s.blast, nil
}

func (s stubGraphRiskService) CascadingBlastRadius(context.Context, string, int) (*risk.CascadingBlastRadiusResult, error) {
	if s.cascading == nil {
		return &risk.CascadingBlastRadiusResult{}, nil
	}
	return s.cascading, nil
}

func (s stubGraphRiskService) ReverseAccess(context.Context, string, int) (*risk.ReverseAccessResult, error) {
	if s.reverse == nil {
		return &risk.ReverseAccessResult{}, nil
	}
	return s.reverse, nil
}

func (s stubGraphRiskService) Rebuild(context.Context) (*graphRebuildResponse, error) {
	if s.rebuild == nil {
		return &graphRebuildResponse{Success: true}, nil
	}
	return s.rebuild, nil
}

func (s stubGraphRiskService) RiskReport(context.Context) (*risk.SecurityReport, error) {
	if s.report == nil {
		return &risk.SecurityReport{}, nil
	}
	return s.report, nil
}

func (s stubGraphRiskService) APISurface(context.Context, graph.APISurfaceReportOptions) (*graph.APISurfaceReport, error) {
	if s.apiSurface == nil {
		return &graph.APISurfaceReport{}, nil
	}
	return s.apiSurface, nil
}

func (s stubGraphRiskService) ToxicCombinations(context.Context) ([]*risk.ToxicCombination, error) {
	return s.toxic, nil
}

func (s stubGraphRiskService) AttackPaths(context.Context, int) (*risk.SimulationResult, error) {
	if s.attackPaths == nil {
		return &risk.SimulationResult{}, nil
	}
	return s.attackPaths, nil
}

func (s stubGraphRiskService) SimulateAttackPathFix(context.Context, string) (*risk.FixSimulation, error) {
	if s.fix == nil {
		return &risk.FixSimulation{}, nil
	}
	return s.fix, nil
}

func (s stubGraphRiskService) Chokepoints(context.Context) ([]*risk.Chokepoint, error) {
	return s.chokepoints, nil
}

func (s stubGraphRiskService) DetectPrivilegeEscalation(context.Context, string) ([]*graph.PrivilegeEscalationRisk, error) {
	return s.escalation, nil
}

func (s stubGraphRiskService) AnalyzePeerGroups(context.Context, float64, int) (*graph.PeerGroupAnalysis, []*graph.OutlierNode, error) {
	if s.peerAnalysis == nil {
		return &graph.PeerGroupAnalysis{}, s.privilegeCreep, nil
	}
	return s.peerAnalysis, s.privilegeCreep, nil
}

func (s stubGraphRiskService) EffectivePermissions(context.Context, string, *graph.PermissionEvaluationContext) (*graph.EffectivePermissions, error) {
	if s.permissions == nil {
		return &graph.EffectivePermissions{}, nil
	}
	return s.permissions, nil
}

func (s stubGraphRiskService) ComparePermissions(context.Context, string, string) (*graph.AccessComparison, error) {
	if s.accessCompare == nil {
		return &graph.AccessComparison{}, nil
	}
	return s.accessCompare, nil
}

func (s stubGraphRiskService) VendorRiskReport(_ context.Context, opts graph.VendorRiskReportOptions) (*graph.VendorRiskReport, error) {
	if s.vendorCapture != nil {
		s.vendorCapture(opts)
	}
	if s.vendorReport == nil {
		return &graph.VendorRiskReport{}, nil
	}
	return s.vendorReport, nil
}

func newGraphRiskServiceTestServer(t *testing.T, service graphRiskService) *Server {
	t.Helper()
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
	})
	s.graphRisk = service
	s.app.SecurityGraph = nil
	s.app.SecurityGraphBuilder = nil
	s.app.graphRuntime = nil
	t.Cleanup(func() {
		s.Close()
	})
	return s
}

func TestGraphRiskTraversalHandlersUseServiceInterface(t *testing.T) {
	now := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	s := newGraphRiskServiceTestServer(t, stubGraphRiskService{
		stats: &graphRiskStatsResponse{
			BuiltAt:       now,
			NodeCount:     7,
			EdgeCount:     9,
			Providers:     []string{"aws"},
			Accounts:      []string{"prod"},
			BuildDuration: "25ms",
		},
		blast: &risk.BlastRadiusResult{
			PrincipalID: "user:alice",
			TotalCount:  1,
		},
		cascading: &risk.CascadingBlastRadiusResult{
			SourceID:        "user:alice",
			MaxCascadeDepth: 2,
		},
		reverse: &risk.ReverseAccessResult{
			ResourceID: "bucket:prod",
			TotalCount: 2,
		},
		rebuild: &graphRebuildResponse{
			Success:       true,
			BuiltAt:       now,
			NodeCount:     11,
			EdgeCount:     14,
			BuildDuration: "40ms",
		},
	})

	w := do(t, s, http.MethodGet, "/api/v1/graph/stats", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if got, ok := body["node_count"].(float64); !ok || got != 7 {
		t.Fatalf("expected service-backed graph stats, got %#v", body["node_count"])
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/blast-radius/user:alice", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body = decodeJSON(t, w)
	if got := body["principal_id"]; got != "user:alice" {
		t.Fatalf("unexpected blast radius principal: %#v", got)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/cascading-blast-radius/user:alice", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body = decodeJSON(t, w)
	if got, ok := body["max_cascade_depth"].(float64); !ok || got != 2 {
		t.Fatalf("expected service-backed cascading blast radius, got %#v", body["max_cascade_depth"])
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/reverse-access/bucket:prod", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body = decodeJSON(t, w)
	if got := body["resource_id"]; got != "bucket:prod" {
		t.Fatalf("unexpected reverse access resource: %#v", got)
	}

	w = do(t, s, http.MethodPost, "/api/v1/graph/rebuild", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body = decodeJSON(t, w)
	if got, ok := body["success"].(bool); !ok || !got {
		t.Fatalf("expected service-backed rebuild response, got %#v", body["success"])
	}
}

func TestGraphRiskIntelligenceHandlersUseServiceInterface(t *testing.T) {
	s := newGraphRiskServiceTestServer(t, stubGraphRiskService{
		report: &risk.SecurityReport{
			RiskScore: 72,
		},
		apiSurface: &graph.APISurfaceReport{
			Count: 1,
			Endpoints: []graph.APISurfaceEndpoint{{
				ID:     "api_endpoint:https://api.example.com",
				URL:    "https://api.example.com",
				Public: true,
			}},
		},
		toxic: []*risk.ToxicCombination{{
			ID:       "tc-1",
			Name:     "Public admin path",
			Severity: risk.SeverityHigh,
			Score:    91,
		}},
		attackPaths: &risk.SimulationResult{
			TotalPaths: 1,
			Paths: []*risk.ScoredAttackPath{{
				ID:         "path-1",
				TotalScore: 9.3,
			}},
		},
		fix: &risk.FixSimulation{
			FixedNode:     "role:admin",
			BlockedCount:  1,
			RiskReduction: 0.4,
		},
		chokepoints: []*risk.Chokepoint{{
			Node:         &graph.Node{ID: "role:admin"},
			PathsThrough: 3,
		}},
	})

	w := do(t, s, http.MethodGet, "/api/v1/graph/risk-report", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if got, ok := body["risk_score"].(float64); !ok || got != 72 {
		t.Fatalf("expected service-backed risk report, got %#v", body["risk_score"])
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/api-surface", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body = decodeJSON(t, w)
	if got, ok := body["count"].(float64); !ok || got != 1 {
		t.Fatalf("expected one API surface endpoint from service, got %#v", body["count"])
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/toxic-combinations", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body = decodeJSON(t, w)
	if got, ok := body["total_count"].(float64); !ok || got != 1 {
		t.Fatalf("expected one toxic combination from service, got %#v", body["total_count"])
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/attack-paths?threshold=5&limit=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body = decodeJSON(t, w)
	if got, ok := body["total_paths"].(float64); !ok || got != 1 {
		t.Fatalf("expected service-backed attack paths, got %#v", body["total_paths"])
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/attack-paths/role:admin/simulate-fix", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body = decodeJSON(t, w)
	if got := body["fixed_node"]; got != "role:admin" {
		t.Fatalf("unexpected fixed node: %#v", got)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/chokepoints", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body = decodeJSON(t, w)
	if got, ok := body["total"].(float64); !ok || got != 1 {
		t.Fatalf("expected one chokepoint from service, got %#v", body["total"])
	}
}

func TestGraphVendorRiskHandlerUsesServiceInterface(t *testing.T) {
	var captured graph.VendorRiskReportOptions
	s := newGraphRiskServiceTestServer(t, stubGraphRiskService{
		vendorReport: &graph.VendorRiskReport{
			Count:      1,
			TotalCount: 2,
			Vendors: []graph.VendorRiskRecord{{
				VendorID:           "vendor:slack",
				Name:               "Slack",
				RiskLevel:          graph.RiskHigh,
				RiskScore:          86,
				VerificationStatus: "verified",
			}},
		},
		vendorCapture: func(opts graph.VendorRiskReportOptions) {
			captured = opts
		},
	})

	resp := do(t, s, http.MethodGet, "/api/v1/graph/vendors?min_score=40&risk=high,medium&verification_status=verified&category=saas_integration&permission_level=admin&limit=10&include_alerts=false&window_days=14", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed vendor risk report, got %d: %s", resp.Code, resp.Body.String())
	}
	if captured.MinRiskScore != 40 || captured.Limit != 10 || captured.IncludeAlerts {
		t.Fatalf("unexpected vendor risk options: %+v", captured)
	}
	if len(captured.RiskLevels) != 2 || captured.RiskLevels[0] != graph.RiskHigh || captured.RiskLevels[1] != graph.RiskMedium {
		t.Fatalf("expected risk filters to reach service, got %+v", captured.RiskLevels)
	}
	if len(captured.VerificationStatuses) != 1 || captured.VerificationStatuses[0] != "verified" {
		t.Fatalf("expected verification filter to reach service, got %+v", captured.VerificationStatuses)
	}
	if len(captured.Categories) != 1 || captured.Categories[0] != "saas_integration" {
		t.Fatalf("expected category filter to reach service, got %+v", captured.Categories)
	}
	if len(captured.PermissionLevels) != 1 || captured.PermissionLevels[0] != "admin" {
		t.Fatalf("expected permission filter to reach service, got %+v", captured.PermissionLevels)
	}
	if captured.MonitoringWindow != 14*24*time.Hour {
		t.Fatalf("expected window_days to reach service, got %s", captured.MonitoringWindow)
	}
	body := decodeJSON(t, resp)
	if got := body["count"]; got != float64(1) {
		t.Fatalf("expected stubbed vendor count, got %#v", got)
	}
}

func TestGraphRiskAccessHandlersUseServiceInterface(t *testing.T) {
	s := newGraphRiskServiceTestServer(t, stubGraphRiskService{
		escalation: []*graph.PrivilegeEscalationRisk{{
			Principal: &graph.Node{ID: "user:alice"},
		}},
		peerAnalysis: &graph.PeerGroupAnalysis{
			TotalPrincipals: 2,
			Groups: []*graph.PeerGroup{{
				ID:          "group-1",
				MemberCount: 2,
				Members:     []string{"user:alice", "user:bob"},
			}},
		},
		privilegeCreep: []*graph.OutlierNode{{
			PrincipalID: "user:alice",
		}},
		permissions: &graph.EffectivePermissions{
			PrincipalID: "user:alice",
			Summary: &graph.PermissionSummary{
				TotalResources: 1,
			},
		},
		accessCompare: &graph.AccessComparison{
			PrincipalA: "user:alice",
			PrincipalB: "user:bob",
			Similarity: 0.5,
		},
	})

	w := do(t, s, http.MethodGet, "/api/v1/graph/privilege-escalation/user:alice", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if got, ok := body["risk_count"].(float64); !ok || got != 1 {
		t.Fatalf("expected service-backed escalation count, got %#v", body["risk_count"])
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/peer-groups", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body = decodeJSON(t, w)
	if got, ok := body["total_principals"].(float64); !ok || got != 2 {
		t.Fatalf("expected service-backed peer groups, got %#v", body["total_principals"])
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/effective-permissions/user:alice", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body = decodeJSON(t, w)
	if got := body["principal_id"]; got != "user:alice" {
		t.Fatalf("unexpected effective permissions principal: %#v", got)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/compare-permissions?principal1=user:alice&principal2=user:bob", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body = decodeJSON(t, w)
	if got := body["principal_a"]; got != "user:alice" {
		t.Fatalf("unexpected comparison principal_a: %#v", got)
	}
}
