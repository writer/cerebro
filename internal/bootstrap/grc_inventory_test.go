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

func TestGRCInventoryAccountabilityOverrideMarksOwnerNotRequired(t *testing.T) {
	asset := graphquery.InventoryAsset{
		URN:        "urn:cerebro:writer:aws_s3_bucket:bucket-a",
		RiskScore:  90,
		ScopeState: grcinventory.ScopeStateInScope,
		Attributes: map[string]string{},
	}
	grcinventory.ApplyScope(&asset, &ports.GRCInventoryScopeRecord{
		TenantID:   "writer",
		AssetURN:   asset.URN,
		ScopeState: grcinventory.ScopeStateInScope,
		Attributes: map[string]string{
			grcinventory.AttributeAccountabilityState:  grcinventory.AccountabilityNone,
			grcinventory.AttributeOwnerNotRequired:     "true",
			grcinventory.AttributeAccountabilityReason: "Ephemeral build artifact",
		},
	})
	grcinventory.ApplyReviewPosture(&asset)
	if asset.Accountability == nil || asset.Accountability.State != grcinventory.AccountabilityNone {
		t.Fatalf("accountability = %#v, want not_required", asset.Accountability)
	}
	if asset.ReviewDisposition == nil || asset.ReviewDisposition.State != grcinventory.ReviewBaseline {
		t.Fatalf("review_disposition = %#v, want baseline", asset.ReviewDisposition)
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

func TestGRCInventoryAccountabilityUpdatePreservesExistingScope(t *testing.T) {
	const assetURN = "urn:cerebro:writer:aws_s3_bucket:bucket-a"
	store := &stubInventoryScopeStore{records: map[string]*ports.GRCInventoryScopeRecord{
		"writer\x00" + assetURN: {
			TenantID:   "writer",
			AssetURN:   assetURN,
			SourceID:   "aws",
			ScopeState: grcinventory.ScopeStateOutScope,
			Reason:     "Not part of audit scope",
			Attributes: map[string]string{"existing": "kept"},
		},
	}}
	record, err := upsertGRCInventoryAccountability(context.Background(), store, "writer", "tester", grcInventoryAccountabilityUpdateRequest{
		AssetURN: assetURN,
		State:    grcinventory.AccountabilityKnown,
		Owner:    "platform@example.com",
		Reason:   "Service owner",
	})
	if err != nil {
		t.Fatalf("upsertGRCInventoryAccountability error = %v", err)
	}
	if record.ScopeState != grcinventory.ScopeStateOutScope || record.Reason != "Not part of audit scope" {
		t.Fatalf("record scope = %q reason = %q, want preserved scope exclusion", record.ScopeState, record.Reason)
	}
	if got := record.Attributes[grcinventory.AttributeAccountabilityPrincipal]; got != "platform@example.com" {
		t.Fatalf("accountability principal = %q, want platform@example.com", got)
	}
	if got := record.Attributes["existing"]; got != "kept" {
		t.Fatalf("existing attribute = %q, want kept", got)
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

type stubInventoryScopeStore struct {
	records map[string]*ports.GRCInventoryScopeRecord
}

func (s *stubInventoryScopeStore) Ping(context.Context) error { return nil }

func (s *stubInventoryScopeStore) UpsertGRCInventoryScope(_ context.Context, record ports.GRCInventoryScopeRecord) (*ports.GRCInventoryScopeRecord, error) {
	if s.records == nil {
		s.records = map[string]*ports.GRCInventoryScopeRecord{}
	}
	cloned := cloneInventoryScopeRecord(&record)
	s.records[inventoryScopeRecordKey(cloned.TenantID, cloned.AssetURN)] = cloned
	return cloneInventoryScopeRecord(cloned), nil
}

func (s *stubInventoryScopeStore) ListGRCInventoryScopes(_ context.Context, filter ports.GRCInventoryScopeFilter) ([]*ports.GRCInventoryScopeRecord, error) {
	if s.records == nil {
		return nil, nil
	}
	urns := map[string]struct{}{}
	for _, urn := range filter.AssetURNs {
		urns[urn] = struct{}{}
	}
	records := []*ports.GRCInventoryScopeRecord{}
	for _, record := range s.records {
		if filter.TenantID != "" && record.TenantID != filter.TenantID {
			continue
		}
		if filter.SourceID != "" && record.SourceID != filter.SourceID {
			continue
		}
		if filter.ScopeState != "" && record.ScopeState != filter.ScopeState {
			continue
		}
		if len(urns) > 0 {
			if _, ok := urns[record.AssetURN]; !ok {
				continue
			}
		}
		records = append(records, cloneInventoryScopeRecord(record))
	}
	return records, nil
}

func inventoryScopeRecordKey(tenantID string, assetURN string) string {
	return tenantID + "\x00" + assetURN
}

func cloneInventoryScopeRecord(record *ports.GRCInventoryScopeRecord) *ports.GRCInventoryScopeRecord {
	if record == nil {
		return nil
	}
	cloned := *record
	if record.Attributes != nil {
		cloned.Attributes = map[string]string{}
		for key, value := range record.Attributes {
			cloned.Attributes[key] = value
		}
	}
	return &cloned
}
