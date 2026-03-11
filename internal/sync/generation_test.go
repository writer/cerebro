package sync

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewSyncGenerationID(t *testing.T) {
	now := time.Date(2026, 3, 7, 15, 4, 5, 123456789, time.UTC)
	got := newSyncGenerationID("AWS", " 123456789012 ", now)
	want := "aws:123456789012:20260307T150405.123456789Z"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNormalizeGenerationComponent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: "unknown"},
		{name: "trim and lowercase", input: "  AWS  ", want: "aws"},
		{name: "replace separators", input: "foo:bar|baz qux", want: "foo_bar_baz_qux"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeGenerationComponent(tt.input); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestGenerationRecordID(t *testing.T) {
	got := generationRecordID("AWS", "123456789012", "aws:123456789012:20260307T150405.123456789Z", "AWS_EC2_INSTANCES", "US-EAST-1")
	want := "aws:123456789012:aws_123456789012_20260307t150405.123456789z:aws_ec2_instances:us-east-1"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestGenerationResultStatus(t *testing.T) {
	tests := []struct {
		name      string
		result    SyncResult
		syncErr   error
		want      string
		wantError string
	}{
		{
			name:      "failed from sync error",
			result:    SyncResult{Table: "aws_ec2_instances"},
			syncErr:   errors.New("boom"),
			want:      "failed",
			wantError: "boom",
		},
		{
			name:      "failed from table error",
			result:    SyncResult{Table: "aws_ec2_instances", Errors: 1, Error: "fetch failed"},
			want:      "failed",
			wantError: "fetch failed",
		},
		{
			name:   "partial from backfill pending",
			result: SyncResult{Table: "aws_ec2_instances", BackfillPending: true},
			want:   "partial",
		},
		{
			name:   "success",
			result: SyncResult{Table: "aws_ec2_instances"},
			want:   "success",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStatus, gotError := generationResultStatus(tt.result, tt.syncErr)
			if gotStatus != tt.want {
				t.Fatalf("expected status %q, got %q", tt.want, gotStatus)
			}
			if gotError != tt.wantError {
				t.Fatalf("expected error %q, got %q", tt.wantError, gotError)
			}
		})
	}
}

func TestSyncDependencyOrder(t *testing.T) {
	tests := []struct {
		table string
		want  int
	}{
		{table: "aws_iam_roles", want: 0},
		{table: "aws_ec2_vpcs", want: 0},
		{table: "aws_lambda_functions", want: 1},
		{table: "aws_ec2_instances", want: 1},
		{table: "aws_securityhub_findings", want: 2},
	}

	for _, tt := range tests {
		if got := syncDependencyOrder(tt.table); got != tt.want {
			t.Fatalf("table %s: expected %d, got %d", tt.table, tt.want, got)
		}
	}
}

func TestDetectSyncStaleness(t *testing.T) {
	base := time.Date(2026, 3, 7, 15, 0, 0, 0, time.UTC)

	t.Run("disabled threshold", func(t *testing.T) {
		_, ok := detectSyncStaleness([]SyncResult{{Table: "a", SyncTime: base}}, 0)
		if ok {
			t.Fatalf("expected disabled threshold to return no alert")
		}
	})

	t.Run("below threshold", func(t *testing.T) {
		results := []SyncResult{
			{Table: "a", Region: "us-east-1", SyncTime: base},
			{Table: "b", Region: "us-east-1", SyncTime: base.Add(2 * time.Minute)},
		}
		_, ok := detectSyncStaleness(results, 5*time.Minute)
		if ok {
			t.Fatalf("expected no alert below threshold")
		}
	})

	t.Run("above threshold ignores errored rows", func(t *testing.T) {
		results := []SyncResult{
			{Table: "errored", Region: "us-east-1", SyncTime: base.Add(-2 * time.Hour), Errors: 1},
			{Table: "oldest", Region: "us-east-1", SyncTime: base},
			{Table: "newest", Region: "us-west-2", SyncTime: base.Add(12 * time.Minute)},
		}
		alert, ok := detectSyncStaleness(results, 5*time.Minute)
		if !ok {
			t.Fatalf("expected staleness alert")
		}
		if alert.Drift != 12*time.Minute {
			t.Fatalf("expected 12m drift, got %s", alert.Drift)
		}
		if alert.Min.Table != "oldest" || alert.Max.Table != "newest" {
			t.Fatalf("unexpected min/max points: %+v", alert)
		}
	})
}

func TestCanExtractRelationships(t *testing.T) {
	required := []string{"aws_ec2_instances", "aws_iam_roles", "aws_lambda_functions"}

	t.Run("all required sources clean", func(t *testing.T) {
		results := []SyncResult{
			{Table: "aws_ec2_instances", Region: "us-east-1", SyncTime: time.Now().UTC()},
			{Table: "aws_iam_roles", Region: "us-east-1", SyncTime: time.Now().UTC()},
			{Table: "aws_lambda_functions", Region: "us-east-1", SyncTime: time.Now().UTC()},
		}
		ok, reason := CanExtractRelationships(results, required)
		if !ok {
			t.Fatalf("expected relationship extraction to be allowed, reason=%q", reason)
		}
		if reason != "" {
			t.Fatalf("expected empty reason for allowed extraction, got %q", reason)
		}
	})

	t.Run("missing and blocked required tables", func(t *testing.T) {
		results := []SyncResult{
			{Table: "aws_ec2_instances", Region: "us-east-1", SyncTime: time.Now().UTC()},
			{Table: "aws_iam_roles", Region: "us-east-1", Errors: 1, Error: "fetch failed"},
		}
		ok, reason := CanExtractRelationships(results, required)
		if ok {
			t.Fatalf("expected relationship extraction to be blocked")
		}
		if !strings.Contains(reason, "missing required source tables: aws_lambda_functions") {
			t.Fatalf("expected missing-table reason, got %q", reason)
		}
		if !strings.Contains(reason, "required source tables not cleanly synced: aws_iam_roles") {
			t.Fatalf("expected blocked-table reason, got %q", reason)
		}
	})

	t.Run("backfill pending blocks extraction", func(t *testing.T) {
		results := []SyncResult{
			{Table: "aws_ec2_instances", Region: "us-east-1", BackfillPending: true},
			{Table: "aws_iam_roles", Region: "us-east-1", SyncTime: time.Now().UTC()},
			{Table: "aws_lambda_functions", Region: "us-east-1", SyncTime: time.Now().UTC()},
		}
		ok, reason := CanExtractRelationships(results, required)
		if ok {
			t.Fatalf("expected relationship extraction to be blocked")
		}
		if !strings.Contains(reason, "aws_ec2_instances") {
			t.Fatalf("expected backfill-pending table in reason, got %q", reason)
		}
	})

	t.Run("required table normalization is case insensitive", func(t *testing.T) {
		results := []SyncResult{
			{Table: "aws_ec2_instances", Region: "us-east-1", SyncTime: time.Now().UTC()},
			{Table: "aws_iam_roles", Region: "us-east-1", SyncTime: time.Now().UTC()},
			{Table: "aws_lambda_functions", Region: "us-east-1", SyncTime: time.Now().UTC()},
		}
		ok, reason := CanExtractRelationships(results, []string{"AWS_EC2_INSTANCES", "aws_iam_roles", " aws_lambda_functions "})
		if !ok {
			t.Fatalf("expected relationship extraction to be allowed, reason=%q", reason)
		}
	})
}

func TestNormalizeRequiredTables(t *testing.T) {
	got := normalizeRequiredTables([]string{" AWS_EC2_INSTANCES ", "aws_ec2_instances", "", "aws_iam_roles"})
	want := []string{"aws_ec2_instances", "aws_iam_roles"}
	if len(got) != len(want) {
		t.Fatalf("expected %d tables, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

func TestWithStalenessThresholdOption(t *testing.T) {
	engine := NewSyncEngine(nil, nil)
	if engine.stalenessThreshold != defaultSyncStalenessThreshold {
		t.Fatalf("expected default threshold %s, got %s", defaultSyncStalenessThreshold, engine.stalenessThreshold)
	}

	custom := 3 * time.Minute
	engine = NewSyncEngine(nil, nil, WithStalenessThreshold(custom))
	if engine.stalenessThreshold != custom {
		t.Fatalf("expected custom threshold %s, got %s", custom, engine.stalenessThreshold)
	}
}
