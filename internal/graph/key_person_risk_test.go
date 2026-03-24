package graph

import (
	"testing"
	"time"
)

func TestBuildKeyPersonRiskReport(t *testing.T) {
	now := time.Now().UTC()
	g := New()
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: map[string]any{"department": "engineering"}})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: map[string]any{"department": "engineering"}})
	g.AddNode(&Node{ID: "person:charlie@example.com", Kind: NodeKindPerson, Name: "Charlie", Properties: map[string]any{"department": "operations"}})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:operations", Kind: NodeKindDepartment, Name: "Operations"})
	g.AddNode(&Node{ID: "svc:core", Kind: NodeKindApplication, Name: "Core"})
	g.AddNode(&Node{ID: "svc:billing", Kind: NodeKindApplication, Name: "Billing"})
	g.AddNode(&Node{ID: "customer:acme", Kind: NodeKindCustomer, Name: "Acme", Properties: map[string]any{"arr": 100000.0}})

	g.AddEdge(&Edge{ID: "alice-eng", Source: "person:alice@example.com", Target: "department:engineering", Kind: EdgeKindMemberOf})
	g.AddEdge(&Edge{ID: "bob-eng", Source: "person:bob@example.com", Target: "department:engineering", Kind: EdgeKindMemberOf})
	g.AddEdge(&Edge{ID: "charlie-ops", Source: "person:charlie@example.com", Target: "department:operations", Kind: EdgeKindMemberOf})

	g.AddEdge(&Edge{ID: "alice-core", Source: "person:alice@example.com", Target: "svc:core", Kind: EdgeKindCanAdmin, Properties: map[string]any{"last_seen": now.Add(-time.Hour)}})
	g.AddEdge(&Edge{ID: "alice-billing", Source: "person:alice@example.com", Target: "svc:billing", Kind: EdgeKindCanAdmin, Properties: map[string]any{"last_seen": now.Add(-time.Hour)}})
	g.AddEdge(&Edge{ID: "bob-billing", Source: "person:bob@example.com", Target: "svc:billing", Kind: EdgeKindCanAdmin, Properties: map[string]any{"last_seen": now.Add(-time.Hour)}})
	g.AddEdge(&Edge{ID: "alice-acme", Source: "person:alice@example.com", Target: "customer:acme", Kind: EdgeKindManagedBy, Properties: map[string]any{"last_seen": now.Add(-time.Hour)}})
	g.AddEdge(&Edge{ID: "alice-bob", Source: "person:alice@example.com", Target: "person:bob@example.com", Kind: EdgeKindInteractedWith, Properties: map[string]any{"last_seen": now.Add(-time.Hour)}})
	g.AddEdge(&Edge{ID: "alice-charlie", Source: "person:alice@example.com", Target: "person:charlie@example.com", Kind: EdgeKindInteractedWith, Properties: map[string]any{"last_seen": now.Add(-time.Hour)}})

	report := BuildKeyPersonRiskReport(g, now, "", 5)
	if report.Count == 0 || len(report.Items) == 0 {
		t.Fatalf("expected ranked key person risk items, got %+v", report)
	}
	first := report.Items[0]
	if first.PersonID != "person:alice@example.com" {
		t.Fatalf("expected alice as top key-person risk, got %+v", first)
	}
	if first.SystemsBusFactor0 < 1 {
		t.Fatalf("expected orphaned systems for alice, got %+v", first)
	}
	if first.CustomersNoContact != 1 {
		t.Fatalf("expected one customer without contact, got %+v", first)
	}
	if first.AffectedARR != 100000 {
		t.Fatalf("expected affected ARR 100000, got %+v", first)
	}
	if first.Risk == RiskNone {
		t.Fatalf("expected non-zero risk level, got %+v", first)
	}

	focused := BuildKeyPersonRiskReport(g, now, "person:alice@example.com", 5)
	if focused.Count != 1 || focused.Items[0].PersonID != "person:alice@example.com" {
		t.Fatalf("expected focused report for alice, got %+v", focused)
	}
}
