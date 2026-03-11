package graph

import (
	"math"
	"strings"
	"testing"
)

func TestRecommendTeam_RanksAndAnalyzesTeam(t *testing.T) {
	g := seedTeamRecommendationGraph()

	result := RecommendTeam(g, TeamRecommendationRequest{
		TargetSystems: []string{"payment-service", "billing-api"},
		Domains:       []string{"payments", "customer-facing"},
		TeamSize:      2,
		Constraints: TeamRecommendationConstraints{
			PreferExistingCollaboration: true,
		},
	})

	if len(result.TargetSystems) != 2 {
		t.Fatalf("expected two resolved target systems, got %+v", result.TargetSystems)
	}
	if len(result.RecommendedTeam) != 2 {
		t.Fatalf("expected two recommended members, got %+v", result.RecommendedTeam)
	}
	if result.RecommendedTeam[0].Person == nil || result.RecommendedTeam[0].Person.ID != "person:alice@example.com" {
		t.Fatalf("expected alice as top recommendation, got %+v", result.RecommendedTeam[0].Person)
	}
	if !containsTeamCandidateID(result.RecommendedTeam, "person:bob@example.com") {
		t.Fatalf("expected bob in recommended team, got %+v", result.RecommendedTeam)
	}

	if result.Analysis.KnowledgeCoverage < 0.99 {
		t.Fatalf("expected full knowledge coverage, got %f", result.Analysis.KnowledgeCoverage)
	}
	if result.Analysis.InternalCohesion < 0.99 {
		t.Fatalf("expected fully cohesive 2-person team, got %f", result.Analysis.InternalCohesion)
	}
	if result.Analysis.ExternalBridges < 1 {
		t.Fatalf("expected at least one external bridge, got %d", result.Analysis.ExternalBridges)
	}
	if math.Abs(result.Analysis.KnowledgeOverlap-0.75) > 0.01 {
		t.Fatalf("expected overlap around 0.75, got %f", result.Analysis.KnowledgeOverlap)
	}
	if len(result.Analysis.GapsIdentified) != 0 {
		t.Fatalf("expected no gaps, got %+v", result.Analysis.GapsIdentified)
	}
	if len(result.Analysis.BusFactorImpacts) == 0 {
		t.Fatalf("expected bus-factor impacts to be present")
	}
}

func TestRecommendTeam_RespectsMaxBusFactorImpact(t *testing.T) {
	g := seedTeamRecommendationGraph()

	result := RecommendTeam(g, TeamRecommendationRequest{
		TargetSystems: []string{"payment-service", "billing-api", "fraud-engine"},
		Domains:       []string{"payments"},
		TeamSize:      3,
		Constraints: TeamRecommendationConstraints{
			MaxBusFactorImpact: 1,
		},
	})

	for _, candidate := range result.RecommendedTeam {
		if candidate.BusFactorImpact > 1 {
			t.Fatalf("expected filtered candidates to have bus-factor impact <= 1, got %+v", result.RecommendedTeam)
		}
	}
	if containsTeamCandidateID(result.RecommendedTeam, "person:alice@example.com") {
		t.Fatalf("alice should be filtered by max_bus_factor_impact=1, got %+v", result.RecommendedTeam)
	}
}

func TestRecommendTeam_SuggestsAlternativeForHighImpactCandidate(t *testing.T) {
	g := seedTeamRecommendationGraph()

	result := RecommendTeam(g, TeamRecommendationRequest{
		TargetSystems: []string{"payment-service", "billing-api"},
		Domains:       []string{"payments"},
		TeamSize:      1,
	})
	if len(result.RecommendedTeam) != 1 {
		t.Fatalf("expected exactly one selected candidate, got %+v", result.RecommendedTeam)
	}

	top := result.RecommendedTeam[0]
	if top.Person == nil || top.Person.ID != "person:alice@example.com" {
		t.Fatalf("expected alice as top pick, got %+v", top.Person)
	}

	alt := findTeamAlternative(result.Alternatives, top.Person.ID)
	if alt == nil {
		t.Fatalf("expected an alternative for %s, got %+v", top.Person.ID, result.Alternatives)
	}
	if strings.TrimSpace(alt.Alternative) == "" || alt.Alternative == top.Person.ID {
		t.Fatalf("expected a distinct alternative, got %+v", alt)
	}
	if !strings.Contains(strings.ToLower(alt.Risk), "reduced") {
		t.Fatalf("expected risk explanation to mention reduction, got %q", alt.Risk)
	}
	if strings.TrimSpace(alt.Tradeoff) == "" {
		t.Fatalf("expected non-empty tradeoff description, got %+v", alt)
	}
}

func seedTeamRecommendationGraph() *Graph {
	g := New()

	g.AddNode(&Node{ID: "system:payment-service", Kind: NodeKindApplication, Name: "payment-service"})
	g.AddNode(&Node{ID: "system:billing-api", Kind: NodeKindRepository, Name: "billing-api"})
	g.AddNode(&Node{ID: "system:fraud-engine", Kind: NodeKindApplication, Name: "fraud-engine"})

	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:support", Kind: NodeKindDepartment, Name: "Support"})
	g.AddNode(&Node{ID: "department:product", Kind: NodeKindDepartment, Name: "Product"})

	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: map[string]any{
		"domains":       []string{"payments", "customer-facing"},
		"skills":        []string{"checkout", "incident-response"},
		"open_issues":   2,
		"team_count":    1,
		"meeting_hours": 4.0,
	}})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: map[string]any{
		"domains":       []string{"payments"},
		"open_issues":   10,
		"team_count":    2,
		"meeting_hours": 10.0,
	}})
	g.AddNode(&Node{ID: "person:carol@example.com", Kind: NodeKindPerson, Name: "Carol", Properties: map[string]any{
		"domains":       []string{"billing"},
		"open_issues":   6,
		"team_count":    1,
		"meeting_hours": 8.0,
	}})
	g.AddNode(&Node{ID: "person:frank@example.com", Kind: NodeKindPerson, Name: "Frank", Properties: map[string]any{
		"domains":       []string{"billing"},
		"open_issues":   1,
		"team_count":    1,
		"meeting_hours": 4.0,
	}})
	g.AddNode(&Node{ID: "person:dave@example.com", Kind: NodeKindPerson, Name: "Dave", Properties: map[string]any{
		"domains": []string{"support"},
	}})

	g.AddEdge(&Edge{ID: "member-alice", Source: "person:alice@example.com", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "member-bob", Source: "person:bob@example.com", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "member-carol", Source: "person:carol@example.com", Target: "department:product", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "member-frank", Source: "person:frank@example.com", Target: "department:product", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "member-dave", Source: "person:dave@example.com", Target: "department:support", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	g.AddEdge(&Edge{ID: "alice-payment", Source: "person:alice@example.com", Target: "system:payment-service", Kind: EdgeKindOwns, Effect: EdgeEffectAllow, Properties: map[string]any{"commit_count": 180}})
	g.AddEdge(&Edge{ID: "alice-billing", Source: "person:alice@example.com", Target: "system:billing-api", Kind: EdgeKindManagedBy, Effect: EdgeEffectAllow, Properties: map[string]any{"review_count": 60}})
	g.AddEdge(&Edge{ID: "alice-fraud", Source: "person:alice@example.com", Target: "system:fraud-engine", Kind: EdgeKindOwns, Effect: EdgeEffectAllow, Properties: map[string]any{"commit_count": 85}})
	g.AddEdge(&Edge{ID: "bob-payment", Source: "person:bob@example.com", Target: "system:payment-service", Kind: EdgeKindManagedBy, Effect: EdgeEffectAllow, Properties: map[string]any{"review_count": 50}})
	g.AddEdge(&Edge{ID: "carol-billing", Source: "person:carol@example.com", Target: "system:billing-api", Kind: EdgeKindManagedBy, Effect: EdgeEffectAllow, Properties: map[string]any{"commit_count": 40}})
	g.AddEdge(&Edge{ID: "frank-billing", Source: "person:frank@example.com", Target: "system:billing-api", Kind: EdgeKindAssignedTo, Effect: EdgeEffectAllow, Properties: map[string]any{"issue_count": 12}})

	g.AddEdge(&Edge{ID: "alice-bob", Source: "person:alice@example.com", Target: "person:bob@example.com", Kind: EdgeKindInteractedWith, Effect: EdgeEffectAllow, Properties: map[string]any{"strength": 0.8}})
	g.AddEdge(&Edge{ID: "alice-dave", Source: "person:alice@example.com", Target: "person:dave@example.com", Kind: EdgeKindInteractedWith, Effect: EdgeEffectAllow, Properties: map[string]any{"strength": 0.6}})

	return g
}

func containsTeamCandidateID(candidates []TeamCandidate, personID string) bool {
	for _, candidate := range candidates {
		if candidate.Person != nil && candidate.Person.ID == personID {
			return true
		}
	}
	return false
}

func findTeamAlternative(alternatives []TeamAlternative, recommendedID string) *TeamAlternative {
	for idx := range alternatives {
		if alternatives[idx].Recommended == recommendedID {
			return &alternatives[idx]
		}
	}
	return nil
}
