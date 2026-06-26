package grcinventory

import (
	"testing"

	"github.com/writer/cerebro/internal/graphquery"
)

func TestSummarizeAssignmentCoverageUsesAssetSurfaceDenominator(t *testing.T) {
	summary := Summarize([]graphquery.InventoryAsset{
		{
			URN:        "urn:cerebro:writer:aws_s3_bucket:bucket-a",
			Surface:    graphquery.InventorySurfaceAsset,
			ScopeState: ScopeStateInScope,
			Attributes: map[string]string{AttributeAccountabilityPrincipal: "platform@example.com"},
		},
		{
			URN:        "urn:cerebro:writer:aws_s3_bucket:bucket-b",
			Surface:    graphquery.InventorySurfaceAsset,
			ScopeState: ScopeStateInScope,
			Attributes: map[string]string{},
		},
		{
			URN:        "urn:cerebro:writer:sentinelone_installed_app:agent-1:app-1",
			Surface:    graphquery.InventorySurfaceComponent,
			ScopeState: ScopeStateInScope,
			Attributes: map[string]string{},
		},
		{
			URN:        "urn:cerebro:writer:aws_account_alias:prod",
			Surface:    graphquery.InventorySurfaceAlias,
			ScopeState: ScopeStateInScope,
			Attributes: map[string]string{},
		},
	})
	if summary.TotalAssets != 4 {
		t.Fatalf("total_assets = %d, want full record count 4", summary.TotalAssets)
	}
	if summary.UnassignedAssets != 1 {
		t.Fatalf("unassigned_assets = %d, want only the unowned asset row", summary.UnassignedAssets)
	}
	if summary.AssignedCoveragePct != 50 {
		t.Fatalf("assigned_coverage_pct = %d, want 50", summary.AssignedCoveragePct)
	}
	if got := summary.SurfaceCounts[graphquery.InventorySurfaceComponent]; got != 1 {
		t.Fatalf("surface_counts[component] = %d, want 1", got)
	}
	if got := summary.SurfaceCounts[graphquery.InventorySurfaceAlias]; got != 1 {
		t.Fatalf("surface_counts[alias] = %d, want 1", got)
	}
}
