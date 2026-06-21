package bootstrap

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestGRCApplyFindingDispositions(t *testing.T) {
	items := []grcFindingItem{{ID: "finding-1"}, {ID: "finding-2"}, {ID: "finding-3"}}
	grcApplyFindingDispositions(items, map[string]string{
		"finding-1": ports.GRCFindingDispositionRiskAccepted,
		"finding-3": ports.GRCFindingDispositionFalsePositive,
		"finding-x": ports.GRCFindingDispositionResolved,
	})

	if items[0].Disposition != ports.GRCFindingDispositionRiskAccepted {
		t.Fatalf("items[0].Disposition = %q, want risk_accepted", items[0].Disposition)
	}
	if items[1].Disposition != "" {
		t.Fatalf("items[1].Disposition = %q, want empty", items[1].Disposition)
	}
	if items[2].Disposition != ports.GRCFindingDispositionFalsePositive {
		t.Fatalf("items[2].Disposition = %q, want false_positive", items[2].Disposition)
	}
}

func TestGRCApplyFindingDispositionsNoop(t *testing.T) {
	items := []grcFindingItem{{ID: "finding-1", GRCFindingWorkflowMetadata: GRCFindingWorkflowMetadata{Disposition: "open"}}}
	grcApplyFindingDispositions(items, nil)
	if items[0].Disposition != "open" {
		t.Fatalf("items[0].Disposition = %q, want unchanged open", items[0].Disposition)
	}
}

func TestGRCFindingDispositionItems(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	records := []*ports.GRCFindingDispositionRecord{
		{FindingID: "finding-1", Disposition: "resolved", UpdatedBy: "alice", UpdatedAt: now},
		nil,
		{FindingID: "finding-2", Disposition: "in_triage", UpdatedAt: now},
	}
	items := grcFindingDispositionItems(records)
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	if items[0].FindingID != "finding-1" || items[0].Disposition != "resolved" || items[0].UpdatedBy != "alice" {
		t.Fatalf("items[0] = %#v", items[0])
	}
	if !items[0].UpdatedAt.Equal(now) {
		t.Fatalf("items[0].UpdatedAt = %v, want %v", items[0].UpdatedAt, now)
	}
	if items[1].FindingID != "finding-2" || items[1].Disposition != "in_triage" {
		t.Fatalf("items[1] = %#v", items[1])
	}
}
