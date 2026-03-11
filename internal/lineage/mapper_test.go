package lineage

import (
	"context"
	"testing"
	"time"
)

func TestLineageMapper_MapKubernetesResource(t *testing.T) {
	mapper := NewLineageMapper()

	resource := map[string]interface{}{
		"kind":       "Deployment",
		"apiVersion": "apps/v1",
		"metadata": map[string]interface{}{
			"name":      "test-app",
			"namespace": "production",
			"labels": map[string]interface{}{
				"app.kubernetes.io/version": "v1.2.3",
			},
			"annotations": map[string]interface{}{
				"cerebro.io/commit-sha":   "abc123def456",
				"cerebro.io/repository":   "org/repo",
				"cerebro.io/branch":       "main",
				"cerebro.io/pipeline-url": "https://github.com/org/repo/actions/runs/123",
			},
		},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"image": "registry.example.com/app:v1.2.3@sha256:abc123",
						},
					},
				},
			},
		},
	}

	lineage, err := mapper.MapKubernetesResource(context.Background(), resource)
	if err != nil {
		t.Fatalf("MapKubernetesResource failed: %v", err)
	}

	if lineage.AssetID != "production/test-app" {
		t.Errorf("got AssetID %s, want production/test-app", lineage.AssetID)
	}

	if lineage.CommitSHA != "abc123def456" {
		t.Errorf("got CommitSHA %s, want abc123def456", lineage.CommitSHA)
	}

	if lineage.Repository != "org/repo" {
		t.Errorf("got Repository %s, want org/repo", lineage.Repository)
	}

	if lineage.ImageTag != "v1.2.3" {
		t.Errorf("got ImageTag %s, want v1.2.3", lineage.ImageTag)
	}

	if lineage.ImageDigest != "sha256:abc123" {
		t.Errorf("got ImageDigest %s, want sha256:abc123", lineage.ImageDigest)
	}
}

func TestLineageMapper_GetLineage(t *testing.T) {
	mapper := NewLineageMapper()

	// Add lineage
	lineage := &AssetLineage{
		AssetID:    "test-asset",
		CommitSHA:  "abc123",
		Repository: "org/repo",
	}
	mapper.assets["test-asset"] = lineage

	// Get lineage
	found, ok := mapper.GetLineage("test-asset")
	if !ok {
		t.Error("expected to find lineage")
	}

	if found.CommitSHA != "abc123" {
		t.Errorf("got CommitSHA %s, want abc123", found.CommitSHA)
	}

	// Get non-existent
	_, ok = mapper.GetLineage("non-existent")
	if ok {
		t.Error("expected not to find non-existent lineage")
	}
}

func TestLineageMapper_GetLineageByCommit(t *testing.T) {
	mapper := NewLineageMapper()

	// Add assets from same commit
	mapper.assets["asset-1"] = &AssetLineage{AssetID: "asset-1", CommitSHA: "commit-abc"}
	mapper.assets["asset-2"] = &AssetLineage{AssetID: "asset-2", CommitSHA: "commit-abc"}
	mapper.assets["asset-3"] = &AssetLineage{AssetID: "asset-3", CommitSHA: "commit-xyz"}

	assets := mapper.GetLineageByCommit("commit-abc")
	if len(assets) != 2 {
		t.Errorf("expected 2 assets, got %d", len(assets))
	}
}

func TestLineageMapper_GetLineageByImage(t *testing.T) {
	mapper := NewLineageMapper()

	// Add assets using same image
	mapper.assets["asset-1"] = &AssetLineage{AssetID: "asset-1", ImageDigest: "sha256:abc123"}
	mapper.assets["asset-2"] = &AssetLineage{AssetID: "asset-2", ImageDigest: "sha256:abc123"}
	mapper.assets["asset-3"] = &AssetLineage{AssetID: "asset-3", ImageDigest: "sha256:xyz789"}

	assets := mapper.GetLineageByImage("sha256:abc123")
	if len(assets) != 2 {
		t.Errorf("expected 2 assets, got %d", len(assets))
	}
}

func TestLineageMapper_DetectDrift(t *testing.T) {
	mapper := NewLineageMapper()

	assetID := "test-asset"
	mapper.assets[assetID] = &AssetLineage{AssetID: assetID}

	currentState := map[string]interface{}{
		"replicas":     3,
		"image":        "app:v2",
		"memory_limit": "512Mi",
		"cpu_limit":    "500m",
	}

	iacState := map[string]interface{}{
		"replicas":     2,        // Different
		"image":        "app:v1", // Different
		"memory_limit": "512Mi",  // Same
		"cpu_limit":    "500m",   // Same
		"extra_config": "value",  // Extra in IaC
	}

	drifts := mapper.DetectDrift(context.Background(), assetID, currentState, iacState)

	// Should detect 3 drifts: replicas, image, extra_config
	if len(drifts) != 3 {
		t.Errorf("expected 3 drifts, got %d", len(drifts))
	}

	// Verify asset is marked as drifted
	asset, _ := mapper.GetLineage(assetID)
	if !asset.DriftDetected {
		t.Error("expected asset to be marked as drifted")
	}
}

func TestParseGitHubActionsContext(t *testing.T) {
	env := map[string]string{
		"GITHUB_REPOSITORY": "org/repo",
		"GITHUB_REF_NAME":   "main",
		"GITHUB_SHA":        "abc123def456",
		"GITHUB_ACTOR":      "user",
		"GITHUB_RUN_ID":     "123456",
		"GITHUB_SERVER_URL": "https://github.com",
	}

	build := ParseGitHubActionsContext(env)

	if build.Provider != "github-actions" {
		t.Errorf("got Provider %s, want github-actions", build.Provider)
	}

	if build.Repository != "org/repo" {
		t.Errorf("got Repository %s, want org/repo", build.Repository)
	}

	if build.CommitSHA != "abc123def456" {
		t.Errorf("got CommitSHA %s, want abc123def456", build.CommitSHA)
	}

	expectedURL := "https://github.com/org/repo/actions/runs/123456"
	if build.URL != expectedURL {
		t.Errorf("got URL %s, want %s", build.URL, expectedURL)
	}
}

func TestParseGitLabCIContext(t *testing.T) {
	env := map[string]string{
		"CI_PROJECT_PATH":    "group/project",
		"CI_COMMIT_REF_NAME": "main",
		"CI_COMMIT_SHA":      "abc123",
		"GITLAB_USER_LOGIN":  "user",
		"CI_PIPELINE_ID":     "789",
		"CI_PIPELINE_URL":    "https://gitlab.com/group/project/-/pipelines/789",
	}

	build := ParseGitLabCIContext(env)

	if build.Provider != "gitlab-ci" {
		t.Errorf("got Provider %s, want gitlab-ci", build.Provider)
	}

	if build.Repository != "group/project" {
		t.Errorf("got Repository %s, want group/project", build.Repository)
	}
}

func TestGenerateLineageID(t *testing.T) {
	id1 := GenerateLineageID("aws", "ec2", "i-1234567890abcdef0")
	id2 := GenerateLineageID("aws", "ec2", "i-1234567890abcdef0")
	id3 := GenerateLineageID("gcp", "vm", "instance-1")

	// Same inputs should produce same ID
	if id1 != id2 {
		t.Error("same inputs should produce same ID")
	}

	// Different inputs should produce different ID
	if id1 == id3 {
		t.Error("different inputs should produce different ID")
	}

	// ID should not be empty
	if id1 == "" {
		t.Error("ID should not be empty")
	}
}

func TestLineageMapper_MapBusinessEntity(t *testing.T) {
	mapper := NewLineageMapper()

	entity := map[string]interface{}{
		"entity_id":             "tenant-123",
		"entity_type":           "tenant",
		"provider":              "application",
		"lead_source":           "partner-referral",
		"lead_id":               "lead-1",
		"contact_id":            "contact-2",
		"deal_id":               "deal-3",
		"contract_id":           "contract-4",
		"subscription_id":       "sub-5",
		"tenant_id":             "tenant-123",
		"crm_entity_id":         "sf-opp-3",
		"billing_entity_id":     "cus-6",
		"support_entity_id":     "zd-org-7",
		"onboarded_at":          "2026-02-01T12:00:00Z",
		"k8s_namespace":         "cust-tenant-123",
		"cloud_resource_id":     "arn:aws:eks:us-west-2:123456789012:cluster/prod",
		"subscriptionStartedAt": "2026-02-02T13:30:00Z",
	}

	lineage, err := mapper.MapBusinessEntity(context.Background(), entity)
	if err != nil {
		t.Fatalf("MapBusinessEntity failed: %v", err)
	}

	if lineage.AssetID != "tenant-123" {
		t.Fatalf("expected asset id tenant-123, got %s", lineage.AssetID)
	}
	if lineage.DealID != "deal-3" {
		t.Fatalf("expected deal id deal-3, got %s", lineage.DealID)
	}
	if lineage.ContractID != "contract-4" {
		t.Fatalf("expected contract id contract-4, got %s", lineage.ContractID)
	}
	if lineage.SubscriptionID != "sub-5" {
		t.Fatalf("expected subscription id sub-5, got %s", lineage.SubscriptionID)
	}
	if lineage.OnboardedAt == nil {
		t.Fatal("expected onboarded_at to be parsed")
	}

	if len(lineage.BusinessChain) == 0 {
		t.Fatal("expected business chain to be populated")
	}
	if !hasBusinessStep(lineage.BusinessChain, BusinessLineageStepOriginatedFrom, "deal-3") {
		t.Fatal("expected deal step in business chain")
	}
	if !hasBusinessStep(lineage.BusinessChain, BusinessLineageStepProvisionedAs, "sub-5") {
		t.Fatal("expected subscription step in business chain")
	}
	if !hasBusinessStep(lineage.BusinessChain, BusinessLineageStepProvisionedAs, "cust-tenant-123") {
		t.Fatal("expected kubernetes namespace step in business chain")
	}
}

func TestLineageMapper_GetLineageByBusinessEntityID(t *testing.T) {
	mapper := NewLineageMapper()

	_, err := mapper.MapBusinessEntity(context.Background(), map[string]interface{}{
		"entity_id":         "tenant-abc",
		"deal_id":           "deal-100",
		"contract_id":       "contract-200",
		"subscription_id":   "sub-300",
		"lead_id":           "lead-400",
		"billing_entity_id": "cus-500",
	})
	if err != nil {
		t.Fatalf("MapBusinessEntity failed: %v", err)
	}

	found, ok := mapper.GetLineage("contract-200")
	if !ok {
		t.Fatal("expected to find lineage by contract id")
	}
	if found.AssetID != "tenant-abc" {
		t.Fatalf("expected tenant-abc lineage, got %s", found.AssetID)
	}

	found, ok = mapper.GetLineage("lead-400")
	if !ok {
		t.Fatal("expected to find lineage by business chain entity id")
	}
	if found.AssetID != "tenant-abc" {
		t.Fatalf("expected tenant-abc lineage from lead lookup, got %s", found.AssetID)
	}
}

func TestLineageMapper_DetectBusinessDrift(t *testing.T) {
	mapper := NewLineageMapper()
	mapper.assets["tenant-xyz"] = &AssetLineage{
		AssetID: "tenant-xyz",
	}

	expectedState := map[string]interface{}{
		"contract_plan":   "enterprise",
		"contract_amount": 5000,
		"crm_stage":       "closed_won",
		"sla_tier":        "enterprise",
	}
	runtimeState := map[string]interface{}{
		"billing_plan":     "pro",
		"billing_amount":   4500,
		"usage_state":      "dormant",
		"support_priority": "p3",
	}

	drifts := mapper.DetectBusinessDrift(context.Background(), "tenant-xyz", expectedState, runtimeState)
	if len(drifts) != 4 {
		t.Fatalf("expected 4 business drifts, got %d", len(drifts))
	}

	lineage, ok := mapper.GetLineage("tenant-xyz")
	if !ok {
		t.Fatal("expected lineage to exist")
	}
	if !lineage.DriftDetected {
		t.Fatal("expected lineage to be marked drifted")
	}
	if len(lineage.DriftDetails) != 4 {
		t.Fatalf("expected 4 stored drift details, got %d", len(lineage.DriftDetails))
	}
}

func TestParseTime_StringUnix(t *testing.T) {
	ts := parseTime("1700000000")
	if ts == nil {
		t.Fatal("expected unix timestamp string to parse")
	}
	if ts.UTC().Unix() != 1700000000 {
		t.Fatalf("unexpected parsed unix value: %d", ts.UTC().Unix())
	}
}

func TestFirstNonEmptyTime(t *testing.T) {
	now := time.Now().UTC()
	got := firstNonEmptyTime(nil, &now)
	if got == nil || !got.Equal(now) {
		t.Fatal("expected first non-nil time to be returned")
	}
}

func hasBusinessStep(steps []BusinessLineageStep, stepType, entityID string) bool {
	for _, step := range steps {
		if step.StepType == stepType && step.EntityID == entityID {
			return true
		}
	}
	return false
}
