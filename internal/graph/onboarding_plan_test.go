package graph

import "testing"

func TestGenerateOnboardingPlan_BuildsFromPeersAndPredecessor(t *testing.T) {
	g := New()

	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "person:nancy@example.com", Kind: NodeKindPerson, Name: "Nancy", Properties: map[string]any{
		"department": "engineering",
		"title":      "Senior Engineer",
		"team":       "payments-platform",
		"status":     "active",
	}})
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: map[string]any{
		"department": "engineering",
		"title":      "Senior Engineer",
		"team":       "payments-platform",
		"status":     "active",
	}})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: map[string]any{
		"department": "engineering",
		"title":      "Senior Engineer",
		"team":       "payments-platform",
		"status":     "active",
	}})
	g.AddNode(&Node{ID: "person:pat@example.com", Kind: NodeKindPerson, Name: "Pat", Properties: map[string]any{
		"department":       "engineering",
		"title":            "Senior Engineer",
		"team":             "payments-platform",
		"status":           "terminated",
		"termination_date": "2026-02-15T00:00:00Z",
	}})
	g.AddNode(&Node{ID: "person:mentor@example.com", Kind: NodeKindPerson, Name: "Mentor", Properties: map[string]any{"status": "active"}})
	g.AddNode(&Node{ID: "person:legacy@example.com", Kind: NodeKindPerson, Name: "Legacy", Properties: map[string]any{"status": "active"}})

	g.AddNode(&Node{ID: "repo:payments", Kind: NodeKindRepository, Name: "payments-repo"})
	g.AddNode(&Node{ID: "repo:billing", Kind: NodeKindRepository, Name: "billing-repo"})
	g.AddNode(&Node{ID: "app:billing-ui", Kind: NodeKindApplication, Name: "Billing UI"})
	g.AddNode(&Node{ID: "group:slack:payments-eng", Kind: NodeKindGroup, Name: "#payments-eng", Properties: map[string]any{"provider": "slack"}})
	g.AddNode(&Node{ID: "activity:project-payments", Kind: NodeKindActivity, Name: "Jira PAY", Properties: map[string]any{"project_key": "PAY"}})
	g.AddNode(&Node{ID: "customer:acme", Kind: NodeKindCustomer, Name: "Acme"})

	g.AddEdge(&Edge{ID: "alice-payments", Source: "person:alice@example.com", Target: "repo:payments", Kind: EdgeKindOwns, Effect: EdgeEffectAllow, Properties: map[string]any{"commit_count": 120}})
	g.AddEdge(&Edge{ID: "bob-payments", Source: "person:bob@example.com", Target: "repo:payments", Kind: EdgeKindManagedBy, Effect: EdgeEffectAllow, Properties: map[string]any{"review_count": 60}})
	g.AddEdge(&Edge{ID: "bob-billing", Source: "person:bob@example.com", Target: "repo:billing", Kind: EdgeKindAssignedTo, Effect: EdgeEffectAllow, Properties: map[string]any{"issue_count": 20}})
	g.AddEdge(&Edge{ID: "pat-payments", Source: "person:pat@example.com", Target: "repo:payments", Kind: EdgeKindManagedBy, Effect: EdgeEffectAllow, Properties: map[string]any{"commit_count": 80}})

	g.AddEdge(&Edge{ID: "alice-mentor", Source: "person:alice@example.com", Target: "person:mentor@example.com", Kind: EdgeKindInteractedWith, Effect: EdgeEffectAllow, Properties: map[string]any{"strength": 0.9}})
	g.AddEdge(&Edge{ID: "bob-mentor", Source: "person:bob@example.com", Target: "person:mentor@example.com", Kind: EdgeKindInteractedWith, Effect: EdgeEffectAllow, Properties: map[string]any{"frequency": 10}})
	g.AddEdge(&Edge{ID: "pat-legacy", Source: "person:pat@example.com", Target: "person:legacy@example.com", Kind: EdgeKindInteractedWith, Effect: EdgeEffectAllow, Properties: map[string]any{"strength": 1.0}})

	g.AddEdge(&Edge{ID: "alice-app", Source: "person:alice@example.com", Target: "app:billing-ui", Kind: EdgeKindCanAdmin, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "bob-app", Source: "person:bob@example.com", Target: "app:billing-ui", Kind: EdgeKindCanWrite, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "alice-channel", Source: "person:alice@example.com", Target: "group:slack:payments-eng", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "bob-channel", Source: "person:bob@example.com", Target: "group:slack:payments-eng", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "alice-project", Source: "person:alice@example.com", Target: "activity:project-payments", Kind: EdgeKindAssignedTo, Effect: EdgeEffectAllow, Properties: map[string]any{"issue_count": 30}})
	g.AddEdge(&Edge{ID: "bob-project", Source: "person:bob@example.com", Target: "activity:project-payments", Kind: EdgeKindAssignedTo, Effect: EdgeEffectAllow, Properties: map[string]any{"issue_count": 15}})

	g.AddEdge(&Edge{ID: "alice-customer", Source: "person:alice@example.com", Target: "customer:acme", Kind: EdgeKindManagedBy, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "pat-customer", Source: "person:pat@example.com", Target: "customer:acme", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})

	plan := GenerateOnboardingPlan(g, "person:nancy@example.com")
	if plan == nil {
		t.Fatal("expected onboarding plan")
	}
	if plan.CohortSize != 2 {
		t.Fatalf("expected cohort size 2, got %d (%+v)", plan.CohortSize, plan.CohortPersonIDs)
	}
	if plan.PredecessorID != "person:pat@example.com" {
		t.Fatalf("expected predecessor person:pat@example.com, got %q", plan.PredecessorID)
	}

	if len(plan.Repositories) == 0 || plan.Repositories[0].RepositoryID != "repo:payments" {
		t.Fatalf("expected repo:payments as top repository, got %+v", plan.Repositories)
	}
	if len(plan.SystemAccess) == 0 || plan.SystemAccess[0].SystemID != "app:billing-ui" {
		t.Fatalf("expected app:billing-ui as top system access recommendation, got %+v", plan.SystemAccess)
	}
	if len(plan.Channels) == 0 || plan.Channels[0].ChannelID != "group:slack:payments-eng" {
		t.Fatalf("expected slack channel recommendation, got %+v", plan.Channels)
	}
	if len(plan.Projects) == 0 || plan.Projects[0].ProjectID != "activity:project-payments" {
		t.Fatalf("expected project recommendation, got %+v", plan.Projects)
	}
	if len(plan.CustomerContext) == 0 || plan.CustomerContext[0].CustomerID != "customer:acme" {
		t.Fatalf("expected customer context recommendation, got %+v", plan.CustomerContext)
	}
	if !containsIntroPerson(plan.KeyPeople, "person:legacy@example.com") {
		t.Fatalf("expected predecessor-derived introduction person:legacy@example.com, got %+v", plan.KeyPeople)
	}
	if containsIntroPerson(plan.KeyPeople, "person:nancy@example.com") {
		t.Fatalf("did not expect new hire to be self-recommended: %+v", plan.KeyPeople)
	}
}

func TestGenerateOnboardingPlan_UnknownPersonReturnsNil(t *testing.T) {
	g := New()
	plan := GenerateOnboardingPlan(g, "person:unknown@example.com")
	if plan != nil {
		t.Fatalf("expected nil plan for unknown person, got %+v", plan)
	}
}

func containsIntroPerson(values []IntroRecommendation, personID string) bool {
	for _, value := range values {
		if value.PersonID == personID {
			return true
		}
	}
	return false
}
