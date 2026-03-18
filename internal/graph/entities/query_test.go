package entities

import (
	"testing"
	"time"

	graph "github.com/writer/cerebro/internal/graph"
)

func TestGetEntityRecordDelegatesToGraphEntityReadModel(t *testing.T) {
	g := graph.New()
	now := time.Now().UTC()
	g.AddNode(&graph.Node{
		ID:        "service:payments",
		Kind:      graph.NodeKindService,
		Name:      "payments",
		CreatedAt: now,
	})

	record, ok := GetEntityRecord(g, "service:payments", now, now)
	if !ok {
		t.Fatal("expected entity record")
	}
	if record.ID != "service:payments" {
		t.Fatalf("unexpected record id %q", record.ID)
	}
	if record.Kind != graph.NodeKindService {
		t.Fatalf("unexpected record kind %q", record.Kind)
	}
}

func TestQueryEntitiesFiltersAndKnowledgeSupport(t *testing.T) {
	g := graph.New()
	baseAt := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	baseProps := map[string]any{
		"observed_at":      baseAt.UTC().Format(time.RFC3339),
		"valid_from":       baseAt.UTC().Format(time.RFC3339),
		"recorded_at":      baseAt.UTC().Format(time.RFC3339),
		"transaction_from": baseAt.UTC().Format(time.RFC3339),
	}

	g.AddNode(&graph.Node{
		ID:         "service:payments",
		Kind:       graph.NodeKindService,
		Name:       "Payments",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Risk:       graph.RiskHigh,
		Findings:   []string{"finding:public-endpoint"},
		Tags:       map[string]string{"env": "prod"},
		Properties: cloneMap(baseProps),
	})
	g.AddNode(&graph.Node{
		ID:         "database:payments",
		Kind:       graph.NodeKindDatabase,
		Name:       "Payments DB",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Risk:       graph.RiskMedium,
		Tags:       map[string]string{"env": "prod"},
		Properties: cloneMap(baseProps),
	})
	g.AddNode(&graph.Node{
		ID:       "arn:aws:s3:::logs",
		Kind:     graph.NodeKindBucket,
		Name:     "Audit Logs",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Risk:     graph.RiskLow,
		Tags:     map[string]string{"env": "prod"},
		Properties: map[string]any{
			"observed_at":         baseAt.UTC().Format(time.RFC3339),
			"valid_from":          baseAt.UTC().Format(time.RFC3339),
			"recorded_at":         baseAt.UTC().Format(time.RFC3339),
			"transaction_from":    baseAt.UTC().Format(time.RFC3339),
			"block_public_acls":   true,
			"block_public_policy": true,
			"logging_enabled":     true,
			"versioning_status":   "Enabled",
			"encrypted":           true,
			"bucket_name":         "logs",
		},
	})
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: cloneMap(baseProps)})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: cloneMap(baseProps)})
	g.AddNode(&graph.Node{ID: "identity_alias:slack:payments-owner", Kind: graph.NodeKindIdentityAlias, Name: "payments-owner", Properties: map[string]any{
		"alias_type":       "slack",
		"source_system":    "slack",
		"observed_at":      baseAt.UTC().Format(time.RFC3339),
		"valid_from":       baseAt.UTC().Format(time.RFC3339),
		"recorded_at":      baseAt.UTC().Format(time.RFC3339),
		"transaction_from": baseAt.UTC().Format(time.RFC3339),
	}})
	g.AddEdge(&graph.Edge{
		ID:         "service:payments->database:payments:depends_on",
		Source:     "service:payments",
		Target:     "database:payments",
		Kind:       graph.EdgeKindDependsOn,
		Effect:     graph.EdgeEffectAllow,
		Properties: cloneMap(baseProps),
	})
	g.AddEdge(&graph.Edge{
		ID:         "identity_alias:slack:payments-owner->person:alice@example.com:alias_of",
		Source:     "identity_alias:slack:payments-owner",
		Target:     "person:alice@example.com",
		Kind:       graph.EdgeKindAliasOf,
		Effect:     graph.EdgeEffectAllow,
		Properties: cloneMap(baseProps),
	})

	g.AddNode(&graph.Node{
		ID:         "evidence:runbook",
		Kind:       graph.NodeKindEvidence,
		Name:       "Runbook",
		Provider:   "cmdb",
		Properties: map[string]any{"evidence_type": "document", "observed_at": baseAt.UTC().Format(time.RFC3339), "valid_from": baseAt.UTC().Format(time.RFC3339), "recorded_at": baseAt.UTC().Format(time.RFC3339), "transaction_from": baseAt.UTC().Format(time.RFC3339)},
	})
	if _, err := graph.WriteObservation(g, graph.ObservationWriteRequest{
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
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
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
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
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
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:              "claim:logs:encrypted:true",
		SubjectID:       "arn:aws:s3:::logs",
		Predicate:       "encrypted",
		ObjectValue:     "true",
		EvidenceIDs:     []string{"evidence:runbook"},
		SourceSystem:    "aws",
		ObservedAt:      baseAt.Add(50 * time.Minute),
		ValidFrom:       baseAt.Add(50 * time.Minute),
		RecordedAt:      baseAt.Add(50 * time.Minute),
		TransactionFrom: baseAt.Add(50 * time.Minute),
	}); err != nil {
		t.Fatalf("write encrypted claim: %v", err)
	}
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:              "claim:logs:public_access:false",
		SubjectID:       "arn:aws:s3:::logs",
		Predicate:       "public_access",
		ObjectValue:     "false",
		EvidenceIDs:     []string{"evidence:runbook"},
		SourceSystem:    "aws",
		ObservedAt:      baseAt.Add(55 * time.Minute),
		ValidFrom:       baseAt.Add(55 * time.Minute),
		RecordedAt:      baseAt.Add(55 * time.Minute),
		TransactionFrom: baseAt.Add(55 * time.Minute),
	}); err != nil {
		t.Fatalf("write public access claim: %v", err)
	}
	graph.NormalizeEntityAssetSupport(g, baseAt.Add(95*time.Minute))

	collection := QueryEntities(g, EntityQueryOptions{
		Categories: []graph.NodeKindCategory{graph.NodeCategoryResource},
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
	if collection.Summary.ResourceEntities != 3 || collection.Summary.KnowledgeBackedEntities != 2 {
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
	if collection.Entities[0].CanonicalRef != nil {
		t.Fatalf("expected list records to omit canonical_ref, got %#v", collection.Entities[0].CanonicalRef)
	}
	if len(collection.Entities[0].ExternalRefs) != 0 || len(collection.Entities[0].Aliases) != 0 {
		t.Fatalf("expected list records to omit detail-only refs and aliases, got %#v", collection.Entities[0])
	}
	for _, entity := range collection.Entities {
		switch entity.Kind {
		case graph.NodeKindBucketPolicyStatement, graph.NodeKindBucketPublicAccessBlock, graph.NodeKindBucketEncryptionConfig, graph.NodeKindBucketLoggingConfig, graph.NodeKindBucketVersioningConfig:
			t.Fatalf("unexpected promoted subresource returned as top-level entity: %#v", entity)
		}
	}
	if len(collection.Entities[0].Relationships) == 0 || collection.Entities[0].Relationships[0].EdgeKind != graph.EdgeKindDependsOn {
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
		Capabilities: []graph.NodeKindCapability{graph.NodeCapabilitySensitiveData},
		HasFindings:  boolPtr(false),
		ValidAt:      baseAt.Add(2 * time.Hour),
		RecordedAt:   baseAt.Add(2 * time.Hour),
	})
	if filtered.Count != 2 {
		t.Fatalf("expected bucket and database for sensitive-data filter, got %#v", filtered.Entities)
	}

	bucketDetail, ok := GetEntityRecord(g, "arn:aws:s3:::logs", baseAt.Add(2*time.Hour), baseAt.Add(2*time.Hour))
	if !ok {
		t.Fatal("expected bucket detail")
	}
	if bucketDetail.CanonicalRef == nil || bucketDetail.CanonicalRef.Namespace != "aws/123456789012/us-east-1" {
		t.Fatalf("unexpected canonical namespace: %#v", bucketDetail.CanonicalRef)
	}
	if len(bucketDetail.ExternalRefs) == 0 || bucketDetail.ExternalRefs[0].Type != "arn" {
		t.Fatalf("expected ARN external ref, got %#v", bucketDetail.ExternalRefs)
	}
	if len(bucketDetail.Facets) < 4 {
		t.Fatalf("expected bucket facets, got %#v", bucketDetail.Facets)
	}
	if bucketDetail.Posture == nil || bucketDetail.Posture.ActiveClaimCount < 2 {
		t.Fatalf("expected bucket posture claims, got %#v", bucketDetail.Posture)
	}
	if len(bucketDetail.Subresources) < 3 {
		t.Fatalf("expected normalized bucket subresources, got %#v", bucketDetail.Subresources)
	}

	personDetail, ok := GetEntityRecord(g, "person:alice@example.com", baseAt.Add(2*time.Hour), baseAt.Add(2*time.Hour))
	if !ok {
		t.Fatal("expected person detail")
	}
	if len(personDetail.Aliases) != 1 || personDetail.Aliases[0].AliasType != "slack" {
		t.Fatalf("expected incoming alias detail, got %#v", personDetail.Aliases)
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func cloneMap(value map[string]any) map[string]any {
	if len(value) == 0 {
		return nil
	}
	clone := make(map[string]any, len(value))
	for key, item := range value {
		clone[key] = item
	}
	return clone
}
