package scanner

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestAdaptiveLimiter_BoundsAcquireAdjustAndRelease(t *testing.T) {
	limiter := NewAdaptiveLimiter(0, 0, 0)
	if limiter.Limit() != 1 {
		t.Fatalf("expected default limit 1, got %d", limiter.Limit())
	}

	if err := limiter.Acquire(context.Background()); err != nil {
		t.Fatalf("acquire should succeed: %v", err)
	}

	// Token is now drained; acquire with a canceled context must return the
	// context error because there are no tokens available.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limiter.Acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled acquire error, got %v", err)
	}

	limiter.Release()

	if got := limiter.Adjust(10); got != 1 {
		t.Fatalf("expected adjust to clamp max=1, got %d", got)
	}
	if got := limiter.Adjust(-2); got != 1 {
		t.Fatalf("expected adjust to clamp min=1, got %d", got)
	}
}

func TestSummarizeSortAndFilterProfiles(t *testing.T) {
	profiles := []TableScanProfile{
		{Table: "aws_s3_buckets", Duration: 3 * time.Second, Scanned: 10, Violations: 2, CacheSkipped: 1},
		{Table: "aws_iam_users", Duration: 1 * time.Second, Scanned: 4, Violations: 1, CacheSkipped: 0},
		{Table: "aws_ec2_instances", Duration: 2 * time.Second, Scanned: 7, Violations: 0, CacheSkipped: 2},
	}

	summary := SummarizeTableProfiles(profiles, 6*time.Second)
	if summary.TotalScanned != 21 || summary.TotalViolations != 3 || summary.TotalSkipped != 3 {
		t.Fatalf("unexpected summary totals: %+v", summary)
	}
	if summary.TotalDuration != 6*time.Second {
		t.Fatalf("expected total duration 6s, got %s", summary.TotalDuration)
	}

	sorted := SortTableProfilesByDuration(profiles)
	if len(sorted) != 3 {
		t.Fatalf("expected sorted length 3, got %d", len(sorted))
	}
	if sorted[0].Table != "aws_s3_buckets" || sorted[1].Table != "aws_ec2_instances" || sorted[2].Table != "aws_iam_users" {
		t.Fatalf("unexpected sort order: %+v", sorted)
	}

	slow := FilterSlowTables(profiles, 2*time.Second)
	if len(slow) != 2 {
		t.Fatalf("expected 2 slow tables, got %d", len(slow))
	}
	if slow[0].Table != "aws_s3_buckets" || slow[1].Table != "aws_ec2_instances" {
		t.Fatalf("unexpected slow table result: %+v", slow)
	}

	if got := FilterSlowTables(profiles, 0); got != nil {
		t.Fatalf("expected nil for non-positive threshold, got %+v", got)
	}
	if got := SortTableProfilesByDuration(nil); got != nil {
		t.Fatalf("expected nil sort output for empty input, got %+v", got)
	}
}

func TestRiskCategoryHelpers(t *testing.T) {
	cats := ParseRiskCategories(" network exposure, data_access, , over-privilege ")
	wantCats := []string{"network exposure", "data_access", "over-privilege"}
	if !reflect.DeepEqual(cats, wantCats) {
		t.Fatalf("unexpected parsed categories: got %v want %v", cats, wantCats)
	}

	if got := CanonicalizeRiskLabel("\"Public Access\""); got != "network_exposure" {
		t.Fatalf("expected network_exposure alias, got %q", got)
	}
	if got := CanonicalizeRiskLabel("data_access"); got != "sensitive_data" {
		t.Fatalf("expected sensitive_data alias, got %q", got)
	}
	if got := CanonicalizeRiskLabel("no_auth"); got != "weak_authentication" {
		t.Fatalf("expected weak_authentication alias, got %q", got)
	}

	canon := CanonicalizeRiskCategories([]string{"public_access", "sensitive_data", "sensitive_data"})
	if len(canon) != 2 || !canon["network_exposure"] || !canon["sensitive_data"] {
		t.Fatalf("unexpected canonical category set: %+v", canon)
	}
	if CanonicalizeRiskCategories(nil) != nil {
		t.Fatal("expected nil canonical set for empty input")
	}

	resourceID := NormalizeResourceID(" \"arn:aws:s3:::bucket\" ")
	if resourceID != "arn:aws:s3:::bucket" {
		t.Fatalf("unexpected normalized resource id: %q", resourceID)
	}

	graphRisks := map[string]bool{"network_exposure": true, "sensitive_data": true}
	sqlRiskSets := map[string][]map[string]bool{
		resourceID: {
			{"network_exposure": true},
			{"network_exposure": true, "sensitive_data": true, "weak_authentication": true},
		},
	}
	if !ShouldSkipGraphToxicCombination(resourceID, graphRisks, sqlRiskSets) {
		t.Fatal("expected graph toxic combination to be skipped when SQL set is a superset")
	}
	if ShouldSkipGraphToxicCombination(resourceID, graphRisks, map[string][]map[string]bool{resourceID: {{"network_exposure": true}}}) {
		t.Fatal("expected graph toxic combination not to be skipped when no SQL superset exists")
	}
}
