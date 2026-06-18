package bootstrap

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/grcinventory"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/resourcescope"
)

func TestGRCInventoryVulnerabilitiesReturnsEmptySlice(t *testing.T) {
	got := grcInventoryVulnerabilities([]grcFindingItem{{ID: "finding-1", Title: "Owner missing", Status: "OPEN"}})
	if got == nil {
		t.Fatal("grcInventoryVulnerabilities() = nil, want empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("grcInventoryVulnerabilities() len = %d, want 0", len(got))
	}
}

func TestGRCInventoryReviewPostureKeepsOrdinaryUnownedAssetsInBaseline(t *testing.T) {
	asset := graphquery.InventoryAsset{
		URN:        "urn:cerebro:writer:github_code_repository:writer/app",
		ScopeState: grcinventory.ScopeStateInScope,
		Attributes: map[string]string{},
	}
	grcinventory.ApplyReviewPosture(&asset)
	if asset.ReviewDisposition == nil || asset.ReviewDisposition.State != grcinventory.ReviewBaseline {
		t.Fatalf("review_disposition = %#v, want baseline", asset.ReviewDisposition)
	}
	if asset.Accountability == nil || asset.Accountability.State != grcinventory.AccountabilityNone {
		t.Fatalf("accountability = %#v, want not_required", asset.Accountability)
	}
}

func TestGRCInventoryReviewPostureRequiresOwnerForHighRiskUnownedAssets(t *testing.T) {
	asset := graphquery.InventoryAsset{
		URN:        "urn:cerebro:writer:aws_s3_bucket:bucket-a",
		RiskScore:  80,
		ScopeState: grcinventory.ScopeStateInScope,
		Attributes: map[string]string{},
	}
	grcinventory.ApplyReviewPosture(&asset)
	if asset.ReviewDisposition == nil || asset.ReviewDisposition.State != grcinventory.ReviewNeedsReview {
		t.Fatalf("review_disposition = %#v, want needs_review", asset.ReviewDisposition)
	}
	if asset.Accountability == nil || asset.Accountability.State != grcinventory.AccountabilityRequired {
		t.Fatalf("accountability = %#v, want required_missing", asset.Accountability)
	}
}

func TestGRCInventoryReviewPostureReportsActiveIssues(t *testing.T) {
	asset := graphquery.InventoryAsset{
		URN:                     "urn:cerebro:writer:aws_s3_bucket:bucket-a",
		ScopeState:              grcinventory.ScopeStateInScope,
		AssetReportCount:        1,
		LatestAssetReportStatus: ports.GRCInventoryAssetReportStatusAccepted,
		Attributes:              map[string]string{},
	}
	grcinventory.ApplyReviewPosture(&asset)
	if asset.ReviewDisposition == nil || asset.ReviewDisposition.State != grcinventory.ReviewReportedIssue {
		t.Fatalf("review_disposition = %#v, want reported_issue", asset.ReviewDisposition)
	}
}

func TestGRCInventoryScopePropagationUpdatesRuntimeResourcePolicy(t *testing.T) {
	const assetURN = "urn:cerebro:writer:aws_s3_bucket:bucket-a"
	store := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"runtime-a": {Id: "runtime-a", TenantId: "writer", SourceId: "aws", Config: map[string]string{}},
	}}
	app := &App{deps: Dependencies{StateStore: store}}

	results, err := app.applyGRCInventoryScopeToSourceRuntimes(context.Background(), "writer", grcInventoryScopeUpdateRequest{
		AssetURN:   assetURN,
		SourceID:   "aws",
		RuntimeID:  "runtime-a",
		ScopeState: grcinventory.ScopeStateOutScope,
		Reason:     "Not in audit scope",
	})
	if err != nil {
		t.Fatalf("applyGRCInventoryScopeToSourceRuntimes(out) error = %v", err)
	}
	if len(results) != 1 || !results[0].ExclusionApplied {
		t.Fatalf("propagation results = %#v, want one applied result", results)
	}
	runtime, err := store.GetSourceRuntime(context.Background(), "runtime-a")
	if err != nil {
		t.Fatalf("GetSourceRuntime(out) error = %v", err)
	}
	policy, err := resourcescope.FromConfig(runtime.GetConfig())
	if err != nil {
		t.Fatalf("FromConfig(out) error = %v", err)
	}
	if !policy.ExcludesEvent("aws_s3_bucket", "bucket-a", map[string]string{"resource_urn": assetURN}) {
		t.Fatalf("scope policy did not exclude %s", assetURN)
	}

	results, err = app.applyGRCInventoryScopeToSourceRuntimes(context.Background(), "writer", grcInventoryScopeUpdateRequest{
		AssetURN:   assetURN,
		SourceID:   "aws",
		RuntimeID:  "runtime-a",
		ScopeState: grcinventory.ScopeStateInScope,
	})
	if err != nil {
		t.Fatalf("applyGRCInventoryScopeToSourceRuntimes(in) error = %v", err)
	}
	if len(results) != 1 || results[0].ExclusionApplied {
		t.Fatalf("propagation results = %#v, want one removal result", results)
	}
	runtime, err = store.GetSourceRuntime(context.Background(), "runtime-a")
	if err != nil {
		t.Fatalf("GetSourceRuntime(in) error = %v", err)
	}
	policy, err = resourcescope.FromConfig(runtime.GetConfig())
	if err != nil {
		t.Fatalf("FromConfig(in) error = %v", err)
	}
	if policy.ExcludesEvent("aws_s3_bucket", "bucket-a", map[string]string{"resource_urn": assetURN}) {
		t.Fatalf("scope policy still excludes %s", assetURN)
	}
	if _, ok := runtime.GetConfig()[resourcescope.ConfigKey]; ok {
		t.Fatalf("runtime config retained empty %s", resourcescope.ConfigKey)
	}
}
