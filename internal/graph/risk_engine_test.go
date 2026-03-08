package graph

import (
	"testing"
	"time"
)

func createTestGraphForRiskEngine() *Graph {
	g := New()

	// Internet entry point
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"})

	// Public-facing web server with vulnerability
	g.AddNode(&Node{
		ID:      "web-server",
		Kind:    NodeKindInstance,
		Name:    "Web Server",
		Account: "123456789012",
		Risk:    RiskHigh,
		Properties: map[string]any{
			"vulnerabilities": []any{"CVE-2021-44228"},
		},
	})
	g.AddEdge(&Edge{
		ID: "internet-to-web", Source: "internet", Target: "web-server",
		Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow,
	})

	// Web server has a role with database access
	g.AddNode(&Node{
		ID:      "web-role",
		Kind:    NodeKindRole,
		Name:    "WebServerRole",
		Account: "123456789012",
	})
	g.AddEdge(&Edge{
		ID: "web-server-assumes", Source: "web-server", Target: "web-role",
		Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow,
	})

	// Production database (crown jewel)
	g.AddNode(&Node{
		ID:      "prod-db",
		Kind:    NodeKindDatabase,
		Name:    "Production Database",
		Account: "123456789012",
		Risk:    RiskCritical,
		Tags:    map[string]string{"contains_pii": "true"},
	})
	g.AddEdge(&Edge{
		ID: "role-to-db", Source: "web-role", Target: "prod-db",
		Kind: EdgeKindCanRead, Effect: EdgeEffectAllow,
	})

	// Secrets store
	g.AddNode(&Node{
		ID:      "secrets",
		Kind:    NodeKindSecret,
		Name:    "API Keys",
		Account: "123456789012",
		Risk:    RiskCritical,
	})
	g.AddEdge(&Edge{
		ID: "role-to-secrets", Source: "web-role", Target: "secrets",
		Kind: EdgeKindCanRead, Effect: EdgeEffectAllow,
	})

	// Admin user without MFA
	g.AddNode(&Node{
		ID:      "admin-user",
		Kind:    NodeKindUser,
		Name:    "Admin User",
		Account: "123456789012",
		Properties: map[string]any{
			"mfa_enabled": false,
		},
	})

	// Admin role
	g.AddNode(&Node{
		ID:      "admin-role",
		Kind:    NodeKindRole,
		Name:    "AdminRole",
		Account: "123456789012",
	})
	g.AddEdge(&Edge{
		ID: "admin-assumes", Source: "admin-user", Target: "admin-role",
		Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow,
	})
	g.AddEdge(&Edge{
		ID: "admin-to-db", Source: "admin-role", Target: "prod-db",
		Kind: EdgeKindCanAdmin, Effect: EdgeEffectAllow,
	})

	// Cross-account access
	g.AddNode(&Node{
		ID:      "external-role",
		Kind:    NodeKindRole,
		Name:    "ExternalPartnerRole",
		Account: "999999999999",
	})
	g.AddEdge(&Edge{
		ID: "external-to-db", Source: "external-role", Target: "prod-db",
		Kind: EdgeKindCanAdmin, Effect: EdgeEffectAllow,
		Properties: map[string]any{"cross_account": true},
	})

	return g
}

func TestRiskEngine_Analyze(t *testing.T) {
	g := createTestGraphForRiskEngine()
	engine := NewRiskEngine(g)

	report := engine.Analyze()

	if report == nil {
		t.Fatal("Expected report, got nil")
	}

	// Check graph stats
	if report.GraphStats.TotalNodes == 0 {
		t.Error("Expected nodes in graph stats")
	}

	t.Logf("Graph stats: %d nodes, %d edges, %d public exposures",
		report.GraphStats.TotalNodes, report.GraphStats.TotalEdges, report.GraphStats.PublicExposures)

	// Check toxic combinations were detected
	if len(report.ToxicCombinations) == 0 {
		t.Error("Expected toxic combinations to be detected")
	}

	for _, tc := range report.ToxicCombinations {
		t.Logf("Toxic Combo: %s (score: %.1f, severity: %s)", tc.Name, tc.Score, tc.Severity)
	}

	// Check attack paths
	if report.AttackPaths.TotalPaths == 0 {
		t.Error("Expected attack paths to be found")
	}

	t.Logf("Attack paths: %d total, %d critical, shortest: %d steps",
		report.AttackPaths.TotalPaths, report.AttackPaths.CriticalPaths, report.AttackPaths.ShortestPath)

	// Check chokepoints
	t.Logf("Chokepoints found: %d", len(report.Chokepoints))
	for _, cp := range report.Chokepoints {
		t.Logf("  Chokepoint: %s (blocks %d paths)", cp.Node.Name, cp.PathsThrough)
	}

	// Check risk score
	if report.RiskScore == 0 {
		t.Error("Expected non-zero risk score")
	}
	t.Logf("Overall risk score: %.1f (%s)", report.RiskScore, report.RiskLevel)

	// Check remediation plan
	if report.RemediationPlan == nil || len(report.RemediationPlan.Steps) == 0 {
		t.Error("Expected remediation plan")
	}
	t.Logf("Remediation: %d steps, %d quick wins, estimated effort: %s",
		len(report.RemediationPlan.Steps), len(report.RemediationPlan.QuickWins), report.RemediationPlan.EstimatedEffort)

	// Check compliance gaps
	t.Logf("Compliance gaps: %d", len(report.ComplianceGaps))
}

func TestToxicCombinationEngine_PublicExposedWithVuln(t *testing.T) {
	g := createTestGraphForRiskEngine()
	engine := NewToxicCombinationEngine()

	results := engine.Analyze(g)

	// Should find the public exposure + vulnerability combo
	foundPublicVuln := false
	for _, tc := range results {
		if tc.Name == "Public Exposure + Vulnerability" {
			foundPublicVuln = true
			if tc.Score < 90 {
				t.Errorf("Expected high score for public+vuln, got %.1f", tc.Score)
			}
			t.Logf("Found: %s (score: %.1f)", tc.Name, tc.Score)
			break
		}
	}

	if !foundPublicVuln {
		t.Error("Expected to find Public Exposure + Vulnerability toxic combination")
	}
}

func TestAttackPathSimulator_Simulate(t *testing.T) {
	g := createTestGraphForRiskEngine()
	sim := NewAttackPathSimulator(g)

	result := sim.Simulate(6)

	if result.EntryPointCount == 0 {
		t.Error("Expected entry points to be identified")
	}
	t.Logf("Entry points: %d, Crown jewels: %d", result.EntryPointCount, result.CrownJewelCount)

	if result.TotalPaths == 0 {
		t.Error("Expected attack paths to be found")
	}

	// Verify path from internet -> web-server -> role -> database exists
	foundPath := false
	for _, path := range result.Paths {
		if path.Target.ID == "prod-db" || path.Target.ID == "secrets" {
			foundPath = true
			t.Logf("Attack path: %s -> %s (length: %d, score: %.1f, skill: %s)",
				path.EntryPoint.Name, path.Target.Name, path.Length, path.TotalScore, path.RequiredSkill)
		}
	}

	if !foundPath {
		t.Error("Expected to find attack path to crown jewels")
	}
}

func TestEffectivePermissionsCalculator(t *testing.T) {
	g := createTestGraphForRiskEngine()
	calc := NewEffectivePermissionsCalculator(g)

	// Test admin user permissions
	ep := calc.Calculate("admin-user")
	if ep == nil {
		t.Fatal("Expected effective permissions")
	}

	t.Logf("Admin user effective permissions: %d resources, %d actions",
		ep.Summary.TotalResources, ep.Summary.TotalActions)

	if ep.Summary.AdminAccess == 0 {
		t.Error("Expected admin user to have admin access")
	}

	// Check risk assessment
	if ep.RiskAssessment.RiskScore == 0 {
		t.Error("Expected non-zero risk score for admin")
	}
	t.Logf("Risk score: %.1f (%s)", ep.RiskAssessment.RiskScore, ep.RiskAssessment.OverallRisk)
}

func TestRiskEngine_SimulateRemediation(t *testing.T) {
	g := createTestGraphForRiskEngine()
	engine := NewRiskEngine(g)

	report := engine.Analyze()

	// Simulate fixing the web server
	impact := engine.SimulateRemediation("web-server")
	if impact == nil {
		t.Fatal("Expected remediation impact")
	}

	t.Logf("Fixing web-server: blocks %d paths, %.1f%% risk reduction",
		impact.BlockedAttackPaths, impact.ReductionPercent)

	if impact.BlockedAttackPaths == 0 {
		t.Error("Expected fixing web-server to block attack paths")
	}

	// Simulate fixing the role (chokepoint)
	if len(report.Chokepoints) > 0 {
		cpImpact := engine.SimulateRemediation(report.Chokepoints[0].Node.ID)
		if cpImpact != nil {
			t.Logf("Fixing chokepoint %s: blocks %d paths, %.1f%% risk reduction",
				report.Chokepoints[0].Node.Name, cpImpact.BlockedAttackPaths, cpImpact.ReductionPercent)
		}
	}
}

func BenchmarkRiskEngine_Analyze(b *testing.B) {
	g := createTestGraphForRiskEngine()
	engine := NewRiskEngine(g)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Analyze()
	}
}

func TestRiskEngine_ScoreEntity_BusinessSignals(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "cust-1",
		Kind: NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"open_p1_tickets":      2,
			"failed_payment_count": 1,
		},
	})
	g.AddNode(&Node{
		ID:   "deal-1",
		Kind: NodeKindDeal,
		Name: "Enterprise Renewal",
		Properties: map[string]any{
			"amount":                   250000,
			"days_since_last_activity": 35,
		},
	})
	g.AddEdge(&Edge{ID: "cust-deal", Source: "cust-1", Target: "deal-1", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})

	engine := NewRiskEngine(g)
	entity := engine.ScoreEntity("cust-1")
	if entity == nil {
		t.Fatal("expected entity score")
	}
	if entity.Score <= 0 {
		t.Fatalf("expected positive entity score, got %.2f", entity.Score)
	}
	if len(entity.Factors) == 0 {
		t.Fatal("expected entity risk factors")
	}
}

func TestRiskEngine_IncludesCustomerTopologyHealth(t *testing.T) {
	now := time.Date(2026, 3, 8, 18, 0, 0, 0, time.UTC)
	prevNow := orgHealthNowUTC
	orgHealthNowUTC = func() time.Time { return now }
	t.Cleanup(func() { orgHealthNowUTC = prevNow })

	g := New()
	g.AddNode(&Node{
		ID:   "cust-1",
		Kind: NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"renewal_days": 45,
		},
	})
	g.AddNode(&Node{ID: "person:owner", Kind: NodeKindPerson, Name: "Owner", Properties: map[string]any{"title": "Account Owner"}})
	g.AddEdge(&Edge{
		ID:     "owner-customer",
		Source: "person:owner",
		Target: "cust-1",
		Kind:   EdgeKindManagedBy,
		Properties: map[string]any{
			"role":               "account_owner",
			"frequency":          1,
			"strength":           0.1,
			"previous_frequency": 5,
			"previous_strength":  0.8,
			"last_seen":          now.Add(-120 * 24 * time.Hour),
		},
	})

	engine := NewRiskEngine(g)
	report := engine.Analyze()
	if len(report.CustomerHealth) == 0 {
		t.Fatal("expected customer topology health metrics in report")
	}

	entity := engine.ScoreEntity("cust-1")
	if entity == nil {
		t.Fatal("expected customer entity score")
	}

	foundTopology := false
	for _, factor := range entity.Factors {
		if factor.Source == "topology" {
			foundTopology = true
			if factor.Score <= 0 {
				t.Fatalf("expected positive topology factor score, got %.2f", factor.Score)
			}
		}
	}
	if !foundTopology {
		t.Fatalf("expected topology factor in entity score, got %+v", entity.Factors)
	}
}

func TestRiskEngine_ProfileInfluencesCompositeScore(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "cust-1",
		Kind: NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"failed_payment_count":      2,
			"open_p1_tickets":           3,
			"days_since_last_activity":  40,
			"investigation_frequency":   4,
			"critical_finding_count":    0,
			"high_finding_count":        0,
			"deploy_frequency_drop_pct": 0,
		},
	})

	engine := NewRiskEngine(g)
	defaultScore := engine.Analyze().RiskScore

	if err := engine.SetRiskProfile("revenue-heavy"); err != nil {
		t.Fatalf("set profile: %v", err)
	}
	revenueScore := engine.Analyze().RiskScore

	if err := engine.SetRiskProfile("security-heavy"); err != nil {
		t.Fatalf("set profile: %v", err)
	}
	securityScore := engine.Analyze().RiskScore

	if revenueScore <= securityScore {
		t.Fatalf("expected revenue-heavy score > security-heavy score (got %.2f vs %.2f, default %.2f)", revenueScore, securityScore, defaultScore)
	}
}

func TestRiskEngine_RiskScoreChangeEvents(t *testing.T) {
	g := New()
	customer := &Node{
		ID:   "cust-1",
		Kind: NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"open_p1_tickets":      1,
			"failed_payment_count": 0,
		},
	}
	g.AddNode(customer)

	engine := NewRiskEngine(g)
	_ = engine.Analyze()

	customer.Properties["open_p1_tickets"] = 8
	customer.Properties["failed_payment_count"] = 6
	customer.Properties["investigation_frequency"] = 10

	events := engine.Analyze().RiskScoreChanges
	if len(events) == 0 {
		t.Fatal("expected threshold crossing events")
	}
}
