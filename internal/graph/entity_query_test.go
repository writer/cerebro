package graph

import (
	"testing"
	"time"
)

func TestQueryEntitiesFiltersAndKnowledgeSupport(t *testing.T) {
	g := New()
	baseAt := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	baseProps := map[string]any{
		"observed_at":      baseAt.UTC().Format(time.RFC3339),
		"valid_from":       baseAt.UTC().Format(time.RFC3339),
		"recorded_at":      baseAt.UTC().Format(time.RFC3339),
		"transaction_from": baseAt.UTC().Format(time.RFC3339),
	}

	g.AddNode(&Node{
		ID:         "service:payments",
		Kind:       NodeKindService,
		Name:       "Payments",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Risk:       RiskHigh,
		Findings:   []string{"finding:public-endpoint"},
		Tags:       map[string]string{"env": "prod"},
		Properties: cloneAnyMap(baseProps),
	})
	g.AddNode(&Node{
		ID:         "database:payments",
		Kind:       NodeKindDatabase,
		Name:       "Payments DB",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Risk:       RiskMedium,
		Tags:       map[string]string{"env": "prod"},
		Properties: cloneAnyMap(baseProps),
	})
	g.AddNode(&Node{
		ID:         "bucket:logs",
		Kind:       NodeKindBucket,
		Name:       "Audit Logs",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Risk:       RiskLow,
		Tags:       map[string]string{"env": "prod"},
		Properties: cloneAnyMap(baseProps),
	})
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: cloneAnyMap(baseProps)})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: cloneAnyMap(baseProps)})
	g.AddEdge(&Edge{
		ID:         "service:payments->database:payments:depends_on",
		Source:     "service:payments",
		Target:     "database:payments",
		Kind:       EdgeKindDependsOn,
		Effect:     EdgeEffectAllow,
		Properties: cloneAnyMap(baseProps),
	})

	g.AddNode(&Node{
		ID:         "evidence:runbook",
		Kind:       NodeKindEvidence,
		Name:       "Runbook",
		Provider:   "cmdb",
		Properties: map[string]any{"evidence_type": "document", "observed_at": baseAt.UTC().Format(time.RFC3339), "valid_from": baseAt.UTC().Format(time.RFC3339), "recorded_at": baseAt.UTC().Format(time.RFC3339), "transaction_from": baseAt.UTC().Format(time.RFC3339)},
	})
	if _, err := WriteObservation(g, ObservationWriteRequest{
		ID:              "observation:payments:manual-review",
		SubjectID:       "service:payments",
		ObservationType: "manual_review_signal",
		Summary:         "Analyst confirmed service ownership context",
		SourceSystem:    "analyst",
		ObservedAt:      baseAt.Add(30 * time.Minute),
		ValidFrom:       baseAt.Add(30 * time.Minute),
		RecordedAt:      baseAt.Add(30 * time.Minute),
		TransactionFrom: baseAt.Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	if _, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:alice",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:alice@example.com",
		EvidenceIDs:     []string{"evidence:runbook"},
		SourceName:      "CMDB",
		SourceType:      "system",
		SourceSystem:    "cmdb",
		ObservedAt:      baseAt.Add(45 * time.Minute),
		ValidFrom:       baseAt.Add(45 * time.Minute),
		RecordedAt:      baseAt.Add(45 * time.Minute),
		TransactionFrom: baseAt.Add(45 * time.Minute),
	}); err != nil {
		t.Fatalf("write alice claim: %v", err)
	}
	if _, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:payments:owner:bob",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:bob@example.com",
		SourceSystem:    "slack",
		ObservedAt:      baseAt.Add(90 * time.Minute),
		ValidFrom:       baseAt.Add(90 * time.Minute),
		RecordedAt:      baseAt.Add(90 * time.Minute),
		TransactionFrom: baseAt.Add(90 * time.Minute),
	}); err != nil {
		t.Fatalf("write bob claim: %v", err)
	}

	collection := QueryEntities(g, EntityQueryOptions{
		Categories: []NodeKindCategory{NodeCategoryResource},
		Provider:   "aws",
		TagKey:     "env",
		TagValue:   "prod",
		ValidAt:    baseAt.Add(2 * time.Hour),
		RecordedAt: baseAt.Add(2 * time.Hour),
		Limit:      10,
	})
	if collection.Count != 3 {
		t.Fatalf("expected three resource entities, got %#v", collection)
	}
	if collection.Summary.ResourceEntities != 3 || collection.Summary.KnowledgeBackedEntities != 1 {
		t.Fatalf("unexpected summary: %#v", collection.Summary)
	}
	if collection.Entities[0].ID != "service:payments" {
		t.Fatalf("expected highest-risk service first, got %#v", collection.Entities[0].ID)
	}
	if collection.Entities[0].Knowledge.ClaimCount != 2 || collection.Entities[0].Knowledge.EvidenceCount != 1 || collection.Entities[0].Knowledge.ObservationCount != 1 {
		t.Fatalf("unexpected knowledge support: %#v", collection.Entities[0].Knowledge)
	}
	if collection.Entities[0].Knowledge.SupportedClaimCount != 1 || collection.Entities[0].Knowledge.ConflictedClaimCount != 2 {
		t.Fatalf("unexpected claim support counts: %#v", collection.Entities[0].Knowledge)
	}
	if len(collection.Entities[0].Relationships) == 0 || collection.Entities[0].Relationships[0].EdgeKind != EdgeKindDependsOn {
		t.Fatalf("expected dependency relationship summary, got %#v", collection.Entities[0].Relationships)
	}

	detail, ok := GetEntityRecord(g, "service:payments", baseAt.Add(2*time.Hour), baseAt.Add(2*time.Hour))
	if !ok {
		t.Fatal("expected service detail")
	}
	if len(detail.Categories) == 0 || len(detail.Capabilities) != 0 {
		t.Fatalf("unexpected categories/capabilities: %#v", detail)
	}
	if detail.Temporal.ValidFrom.IsZero() || detail.Temporal.RecordedAt.IsZero() {
		t.Fatalf("expected temporal metadata, got %#v", detail.Temporal)
	}

	filtered := QueryEntities(g, EntityQueryOptions{
		Capabilities: []NodeKindCapability{NodeCapabilitySensitiveData},
		HasFindings:  boolPtr(false),
		ValidAt:      baseAt.Add(2 * time.Hour),
		RecordedAt:   baseAt.Add(2 * time.Hour),
	})
	if filtered.Count != 2 {
		t.Fatalf("expected bucket and database for sensitive-data filter, got %#v", filtered.Entities)
	}
}

func boolPtr(value bool) *bool {
	return &value
}
