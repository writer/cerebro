package graph

import (
	"testing"
	"time"
)

func TestWhoKnows_SystemRanksPrimaryAndRoutingCandidates(t *testing.T) {
	now := time.Date(2026, 3, 8, 16, 0, 0, 0, time.UTC)
	prevNow := orgHealthNowUTC
	orgHealthNowUTC = func() time.Time { return now }
	t.Cleanup(func() { orgHealthNowUTC = prevNow })

	g := New()
	g.AddNode(&Node{ID: "system:payment-service", Kind: NodeKindApplication, Name: "payment-service"})
	g.AddNode(&Node{ID: "customer:northwind", Kind: NodeKindCustomer, Name: "Northwind", Properties: map[string]any{"arr": 900000.0}})
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: map[string]any{"status": "active"}})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: map[string]any{"status": "active"}})
	g.AddNode(&Node{ID: "person:carol@example.com", Kind: NodeKindPerson, Name: "Carol", Properties: map[string]any{"status": "active"}})
	g.AddNode(&Node{ID: "person:dan@example.com", Kind: NodeKindPerson, Name: "Dan", Properties: map[string]any{"status": "on_leave"}})

	g.AddEdge(&Edge{
		ID:     "alice-system",
		Source: "person:alice@example.com",
		Target: "system:payment-service",
		Kind:   EdgeKindManagedBy,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"role":         "primary_maintainer",
			"commit_count": 340,
			"last_seen":    now.Add(-2 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "bob-system",
		Source: "person:bob@example.com",
		Target: "system:payment-service",
		Kind:   EdgeKindAssignedTo,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"review_count": 45,
			"last_seen":    now.Add(-36 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "dan-system",
		Source: "person:dan@example.com",
		Target: "system:payment-service",
		Kind:   EdgeKindOwns,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"role":         "former_owner",
			"commit_count": 8,
			"last_seen":    now.Add(-240 * 24 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "alice-customer",
		Source: "person:alice@example.com",
		Target: "customer:northwind",
		Kind:   EdgeKindManagedBy,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"role":      "account_owner",
			"last_seen": now.Add(-24 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "alice-carol",
		Source: "person:alice@example.com",
		Target: "person:carol@example.com",
		Kind:   EdgeKindInteractedWith,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"frequency": 28,
			"strength":  1.8,
			"last_seen": now.Add(-3 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "alice-bob",
		Source: "person:alice@example.com",
		Target: "person:bob@example.com",
		Kind:   EdgeKindInteractedWith,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"frequency": 12,
			"strength":  1.2,
			"last_seen": now.Add(-8 * time.Hour),
		},
	})

	result := WhoKnows(g, KnowledgeQuery{System: "payment-service", Limit: 3})
	if len(result.Targets) != 1 || result.Targets[0].ID != "system:payment-service" {
		t.Fatalf("expected system target match, got %+v", result.Targets)
	}
	if result.Count != 3 || len(result.Candidates) != 3 {
		t.Fatalf("expected 3 candidates, got count=%d candidates=%d", result.Count, len(result.Candidates))
	}

	if got := result.Candidates[0].Person.ID; got != "person:alice@example.com" {
		t.Fatalf("expected Alice to rank first, got %s", got)
	}
	if result.Candidates[0].Relationship != "primary maintainer" {
		t.Fatalf("expected top relationship to be primary maintainer, got %q", result.Candidates[0].Relationship)
	}
	if result.Candidates[0].KnowledgeScore <= 0.5 {
		t.Fatalf("expected top candidate score > 0.5, got %.3f", result.Candidates[0].KnowledgeScore)
	}

	if !hasCandidateID(result.Candidates, "person:bob@example.com") {
		t.Fatalf("expected Bob in ranked candidates, got %+v", candidateIDs(result.Candidates))
	}
	if !hasCandidateID(result.Candidates, "person:carol@example.com") {
		t.Fatalf("expected Carol in ranked candidates (routing fallback), got %+v", candidateIDs(result.Candidates))
	}
}

func TestWhoKnows_AvailableOnlyFiltersUnavailableExperts(t *testing.T) {
	now := time.Date(2026, 3, 8, 16, 0, 0, 0, time.UTC)
	prevNow := orgHealthNowUTC
	orgHealthNowUTC = func() time.Time { return now }
	t.Cleanup(func() { orgHealthNowUTC = prevNow })

	g := New()
	g.AddNode(&Node{ID: "system:auth-svc", Kind: NodeKindApplication, Name: "auth-svc"})
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: map[string]any{"status": "on_leave"}})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: map[string]any{"status": "active"}})

	g.AddEdge(&Edge{
		ID:     "alice-auth",
		Source: "person:alice@example.com",
		Target: "system:auth-svc",
		Kind:   EdgeKindManagedBy,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"commit_count": 400,
			"last_seen":    now.Add(-2 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "bob-auth",
		Source: "person:bob@example.com",
		Target: "system:auth-svc",
		Kind:   EdgeKindAssignedTo,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"review_count": 60,
			"last_seen":    now.Add(-6 * time.Hour),
		},
	})

	unfiltered := WhoKnows(g, KnowledgeQuery{System: "auth-svc", Limit: 5})
	alice := findKnowledgeCandidate(unfiltered.Candidates, "person:alice@example.com")
	if alice == nil || alice.Available {
		t.Fatalf("expected Alice to be present but unavailable, got %+v", alice)
	}

	availableOnly := WhoKnows(g, KnowledgeQuery{System: "auth-svc", AvailableOnly: true, Limit: 5})
	if hasCandidateID(availableOnly.Candidates, "person:alice@example.com") {
		t.Fatalf("expected unavailable Alice to be filtered out, got %+v", candidateIDs(availableOnly.Candidates))
	}
	if len(availableOnly.Candidates) != 1 || availableOnly.Candidates[0].Person.ID != "person:bob@example.com" {
		t.Fatalf("expected Bob as only available candidate, got %+v", candidateIDs(availableOnly.Candidates))
	}
}

func TestWhoKnows_CustomerQuery(t *testing.T) {
	now := time.Date(2026, 3, 8, 16, 0, 0, 0, time.UTC)
	prevNow := orgHealthNowUTC
	orgHealthNowUTC = func() time.Time { return now }
	t.Cleanup(func() { orgHealthNowUTC = prevNow })

	g := New()
	g.AddNode(&Node{ID: "customer:northwind", Kind: NodeKindCustomer, Name: "Northwind"})
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: map[string]any{"status": "active"}})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: map[string]any{"status": "active"}})

	g.AddEdge(&Edge{
		ID:     "alice-customer",
		Source: "person:alice@example.com",
		Target: "customer:northwind",
		Kind:   EdgeKindManagedBy,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"role":      "account_owner",
			"last_seen": now.Add(-4 * time.Hour),
		},
	})
	g.AddEdge(&Edge{
		ID:     "bob-customer",
		Source: "person:bob@example.com",
		Target: "customer:northwind",
		Kind:   EdgeKindAssignedTo,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"last_seen": now.Add(-72 * time.Hour),
		},
	})

	result := WhoKnows(g, KnowledgeQuery{Customer: "northwind", Limit: 2})
	if len(result.Targets) != 1 || result.Targets[0].ID != "customer:northwind" {
		t.Fatalf("expected customer target, got %+v", result.Targets)
	}
	if len(result.Candidates) == 0 || result.Candidates[0].Person.ID != "person:alice@example.com" {
		t.Fatalf("expected Alice to rank first for customer query, got %+v", candidateIDs(result.Candidates))
	}
}

func hasCandidateID(candidates []KnowledgeCandidate, personID string) bool {
	for _, candidate := range candidates {
		if candidate.Person != nil && candidate.Person.ID == personID {
			return true
		}
	}
	return false
}

func findKnowledgeCandidate(candidates []KnowledgeCandidate, personID string) *KnowledgeCandidate {
	for idx := range candidates {
		if candidates[idx].Person != nil && candidates[idx].Person.ID == personID {
			return &candidates[idx]
		}
	}
	return nil
}

func candidateIDs(candidates []KnowledgeCandidate) []string {
	ids := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Person == nil {
			continue
		}
		ids = append(ids, candidate.Person.ID)
	}
	return ids
}
