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
		ID:       "arn:aws:s3:::logs",
		Kind:     NodeKindBucket,
		Name:     "Audit Logs",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Risk:     RiskLow,
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
	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: cloneAnyMap(baseProps)})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: cloneAnyMap(baseProps)})
	g.AddNode(&Node{ID: "identity_alias:slack:payments-owner", Kind: NodeKindIdentityAlias, Name: "payments-owner", Properties: map[string]any{
		"alias_type":       "slack",
		"source_system":    "slack",
		"observed_at":      baseAt.UTC().Format(time.RFC3339),
		"valid_from":       baseAt.UTC().Format(time.RFC3339),
		"recorded_at":      baseAt.UTC().Format(time.RFC3339),
		"transaction_from": baseAt.UTC().Format(time.RFC3339),
	}})
	g.AddEdge(&Edge{
		ID:         "service:payments->database:payments:depends_on",
		Source:     "service:payments",
		Target:     "database:payments",
		Kind:       EdgeKindDependsOn,
		Effect:     EdgeEffectAllow,
		Properties: cloneAnyMap(baseProps),
	})
	g.AddEdge(&Edge{
		ID:         "identity_alias:slack:payments-owner->person:alice@example.com:alias_of",
		Source:     "identity_alias:slack:payments-owner",
		Target:     "person:alice@example.com",
		Kind:       EdgeKindAliasOf,
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
	if _, err := WriteClaim(g, ClaimWriteRequest{
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
	if _, err := WriteClaim(g, ClaimWriteRequest{
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
	NormalizeEntityAssetSupport(g, baseAt.Add(95*time.Minute))

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
		case NodeKindBucketPolicyStatement, NodeKindBucketPublicAccessBlock, NodeKindBucketEncryptionConfig, NodeKindBucketLoggingConfig, NodeKindBucketVersioningConfig:
			t.Fatalf("unexpected promoted subresource returned as top-level entity: %#v", entity)
		}
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

func TestNormalizeEntityAssetSupportUsesBucketFallbacksForLoggingAndVersioning(t *testing.T) {
	g := New()
	baseAt := time.Date(2026, 3, 10, 11, 0, 0, 0, time.UTC)
	bucketID := "arn:aws:s3:::audit-logs"
	props := map[string]any{
		"observed_at":      baseAt.UTC().Format(time.RFC3339),
		"valid_from":       baseAt.UTC().Format(time.RFC3339),
		"recorded_at":      baseAt.UTC().Format(time.RFC3339),
		"transaction_from": baseAt.UTC().Format(time.RFC3339),
		"logging_enabled":  true,
		"mfa_delete":       "Disabled",
		"bucket_name":      "audit-logs",
	}
	g.AddNode(&Node{
		ID:         bucketID,
		Kind:       NodeKindBucket,
		Name:       "Audit Logs",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Properties: cloneAnyMap(props),
	})
	g.AddNode(&Node{
		ID:         "bucket_logging_config:" + slugifyKnowledgeKey(bucketID),
		Kind:       NodeKindBucketLoggingConfig,
		Name:       "Bucket Logging Configuration",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Properties: cloneAnyMap(props),
	})
	if _, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:" + slugifyKnowledgeKey(bucketID) + ":bucket_logging_config:normalized",
		SubjectID:       bucketID,
		Predicate:       "access_logging_enabled",
		ObjectValue:     "false",
		SourceSystem:    "test",
		ObservedAt:      baseAt.Add(12 * time.Hour),
		ValidFrom:       baseAt.Add(12 * time.Hour),
		RecordedAt:      baseAt.Add(12 * time.Hour),
		TransactionFrom: baseAt.Add(12 * time.Hour),
	}); err != nil {
		t.Fatalf("write future logging claim: %v", err)
	}

	result := NormalizeEntityAssetSupport(g, baseAt.Add(time.Hour))
	if result.SubresourcesCreated == 0 {
		t.Fatalf("expected normalization to create subresources, got %#v", result)
	}

	loggingClaimID := "claim:" + slugifyKnowledgeKey(bucketID) + ":" + slugifyKnowledgeKey("access_logging_enabled") + ":normalized"
	loggingClaim, ok := GetClaimRecord(g, loggingClaimID, baseAt.Add(2*time.Hour), baseAt.Add(2*time.Hour))
	if !ok {
		t.Fatalf("expected normalized logging claim %q", loggingClaimID)
	}
	if loggingClaim.ObjectValue != "true" {
		t.Fatalf("expected logging fallback to preserve true bucket property, got %#v", loggingClaim.ObjectValue)
	}

	detail, ok := GetEntityRecord(g, bucketID, baseAt.Add(2*time.Hour), baseAt.Add(2*time.Hour))
	if !ok {
		t.Fatal("expected bucket detail")
	}
	foundVersioning := false
	for _, subresource := range detail.Subresources {
		if subresource.Kind != NodeKindBucketVersioningConfig {
			continue
		}
		foundVersioning = true
		if status := readString(subresource.Fields, "versioning_status"); status != "disabled" {
			t.Fatalf("expected explicit disabled versioning status, got %#v", subresource.Fields)
		}
		if _, ok := subresource.Fields["mfa_delete"]; !ok {
			t.Fatalf("expected mfa_delete field to be preserved, got %#v", subresource.Fields)
		}
	}
	if !foundVersioning {
		t.Fatalf("expected versioning subresource for explicit mfa_delete state, got %#v", detail.Subresources)
	}
	foundVersioningFacet := false
	for _, facet := range detail.Facets {
		if facet.ID != "bucket_versioning" {
			continue
		}
		foundVersioningFacet = true
		if facet.Status != "present" {
			t.Fatalf("expected explicit disabled mfa_delete state to yield a present versioning facet, got %#v", facet)
		}
		if status := readString(facet.Fields, "versioning_status"); status != "disabled" {
			t.Fatalf("expected disabled versioning status in facet fields, got %#v", facet.Fields)
		}
		if mfaDelete, ok := facet.Fields["mfa_delete"].(bool); !ok || mfaDelete {
			t.Fatalf("expected explicit Disabled mfa_delete to normalize to false in facet fields, got %#v", facet.Fields)
		}
	}
	if !foundVersioningFacet {
		t.Fatalf("expected bucket_versioning facet, got %#v", detail.Facets)
	}
}

func TestNormalizeEntityAssetSupportUsesBucketVersioningFallbackAndEnabledStrings(t *testing.T) {
	g := New()
	baseAt := time.Date(2026, 3, 10, 13, 0, 0, 0, time.UTC)
	bucketID := "arn:aws:s3:::versioned-logs"
	props := map[string]any{
		"observed_at":       baseAt.UTC().Format(time.RFC3339),
		"valid_from":        baseAt.UTC().Format(time.RFC3339),
		"recorded_at":       baseAt.UTC().Format(time.RFC3339),
		"transaction_from":  baseAt.UTC().Format(time.RFC3339),
		"versioning_status": "Enabled",
		"mfa_delete":        "Enabled",
		"bucket_name":       "versioned-logs",
	}
	g.AddNode(&Node{
		ID:         bucketID,
		Kind:       NodeKindBucket,
		Name:       "Versioned Logs",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Properties: cloneAnyMap(props),
	})
	if _, err := WriteClaim(g, ClaimWriteRequest{
		ID:              "claim:" + slugifyKnowledgeKey(bucketID) + ":bucket_versioning_config:normalized",
		SubjectID:       bucketID,
		Predicate:       "versioning_enabled",
		ObjectValue:     "false",
		SourceSystem:    "test",
		ObservedAt:      baseAt.Add(12 * time.Hour),
		ValidFrom:       baseAt.Add(12 * time.Hour),
		RecordedAt:      baseAt.Add(12 * time.Hour),
		TransactionFrom: baseAt.Add(12 * time.Hour),
	}); err != nil {
		t.Fatalf("write future versioning claim: %v", err)
	}

	NormalizeEntityAssetSupport(g, baseAt.Add(time.Hour))

	versioningClaimID := "claim:" + slugifyKnowledgeKey(bucketID) + ":" + slugifyKnowledgeKey("versioning_enabled") + ":normalized"
	versioningClaim, ok := GetClaimRecord(g, versioningClaimID, baseAt.Add(2*time.Hour), baseAt.Add(2*time.Hour))
	if !ok {
		t.Fatalf("expected normalized versioning claim %q", versioningClaimID)
	}
	if versioningClaim.ObjectValue != "true" {
		t.Fatalf("expected versioning fallback to preserve enabled bucket property, got %#v", versioningClaim.ObjectValue)
	}

	detail, ok := GetEntityRecord(g, bucketID, baseAt.Add(2*time.Hour), baseAt.Add(2*time.Hour))
	if !ok {
		t.Fatal("expected bucket detail")
	}
	foundVersioning := false
	for _, subresource := range detail.Subresources {
		if subresource.Kind != NodeKindBucketVersioningConfig {
			continue
		}
		foundVersioning = true
		if status := readString(subresource.Fields, "versioning_status"); status != "enabled" {
			t.Fatalf("expected enabled versioning status, got %#v", subresource.Fields)
		}
		if mfaDelete, ok := subresource.Fields["mfa_delete"].(bool); !ok || !mfaDelete {
			t.Fatalf("expected AWS Enabled string to normalize to mfa_delete=true, got %#v", subresource.Fields)
		}
	}
	if !foundVersioning {
		t.Fatalf("expected versioning subresource, got %#v", detail.Subresources)
	}
}

func TestNormalizeEntityAssetSupportPromotesMultipleBucketPolicyStatements(t *testing.T) {
	g := New()
	baseAt := time.Date(2026, 3, 10, 14, 0, 0, 0, time.UTC)
	bucketID := "arn:aws:s3:::public-bucket"
	props := map[string]any{
		"observed_at":                     baseAt.UTC().Format(time.RFC3339),
		"valid_from":                      baseAt.UTC().Format(time.RFC3339),
		"recorded_at":                     baseAt.UTC().Format(time.RFC3339),
		"transaction_from":                baseAt.UTC().Format(time.RFC3339),
		"all_users_access":                true,
		"all_users_actions":               []string{"s3:GetObject"},
		"all_authenticated_users_access":  true,
		"all_authenticated_users_actions": []string{"s3:GetObject", "s3:ListBucket"},
		"bucket_name":                     "public-bucket",
	}
	g.AddNode(&Node{
		ID:         bucketID,
		Kind:       NodeKindBucket,
		Name:       "Public Bucket",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Properties: cloneAnyMap(props),
	})

	result := NormalizeEntityAssetSupport(g, baseAt.Add(time.Hour))
	if result.SubresourcesCreated < 2 {
		t.Fatalf("expected multiple policy-statement subresources, got %#v", result)
	}

	detail, ok := GetEntityRecord(g, bucketID, baseAt.Add(2*time.Hour), baseAt.Add(2*time.Hour))
	if !ok {
		t.Fatal("expected bucket detail")
	}
	statementCount := 0
	actionCounts := make(map[string]int)
	publicAccessFacetMatched := false
	for _, subresource := range detail.Subresources {
		if subresource.Kind == NodeKindBucketPolicyStatement {
			statementCount++
			actionCounts[readString(subresource.Fields, "principal_type")] = int(readFloat(subresource.Fields, "action_count"))
		}
	}
	for _, facet := range detail.Facets {
		if facet.ID != "bucket_public_access" {
			continue
		}
		publicAccessFacetMatched = true
		if publicAccess, ok := facet.Fields["public_access"].(bool); !ok || !publicAccess {
			t.Fatalf("expected public_access facet field to reflect promoted public signals, got %#v", facet)
		}
	}
	if statementCount != 2 {
		t.Fatalf("expected two policy statement subresources, got %#v", detail.Subresources)
	}
	if actionCounts["all_users"] != 1 || actionCounts["all_authenticated_users"] != 2 {
		t.Fatalf("expected per-principal action counts, got %#v", actionCounts)
	}
	if !publicAccessFacetMatched {
		t.Fatalf("expected bucket_public_access facet, got %#v", detail.Facets)
	}
}
