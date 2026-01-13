package lineage

import (
	"context"
	"testing"
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
