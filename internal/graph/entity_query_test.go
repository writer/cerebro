package graph

import (
	"testing"
	"time"
)

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
