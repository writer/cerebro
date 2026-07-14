package postgres

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestNormalizeInputSnapshotRequestRequiresStableScope(t *testing.T) {
	cutoff := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	request, err := normalizeInputSnapshotRequest(ports.InputSnapshotRequest{
		TenantID:   " tenant-a ",
		RuntimeIDs: []string{"runtime-b", "runtime-a", "runtime-a", " "},
		Cutoff:     cutoff,
	})
	if err != nil {
		t.Fatalf("normalizeInputSnapshotRequest() error = %v", err)
	}
	if request.TenantID != "tenant-a" || request.Limit != defaultInputSnapshotPageSize || !request.Cutoff.Equal(cutoff) {
		t.Fatalf("normalized request = %+v", request)
	}
	if len(request.RuntimeIDs) != 2 || request.RuntimeIDs[0] != "runtime-b" || request.RuntimeIDs[1] != "runtime-a" {
		t.Fatalf("runtime ids = %v", request.RuntimeIDs)
	}

	cases := []ports.InputSnapshotRequest{
		{RuntimeIDs: []string{"runtime-a"}, Cutoff: cutoff},
		{TenantID: "tenant-a", Cutoff: cutoff},
		{TenantID: "tenant-a", RuntimeIDs: []string{"runtime-a"}},
		{TenantID: "tenant-a", RuntimeIDs: []string{"runtime-a"}, Cutoff: cutoff, Limit: maxInputSnapshotPageSize + 1},
	}
	for _, invalid := range cases {
		if _, err := normalizeInputSnapshotRequest(invalid); err == nil {
			t.Fatalf("normalizeInputSnapshotRequest(%+v) error = nil", invalid)
		}
	}
}

func TestFinishInputSnapshotPageUsesKeysetCursor(t *testing.T) {
	cutoff := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	watermark := cutoff.Add(-time.Minute)
	page := finishInputSnapshotPage([]string{"a", "b", "c"}, ports.InputSnapshotRequest{Limit: 2, Cutoff: cutoff}, 3, watermark, func(value string) string { return value })
	if page.Complete || page.NextCursor != "b" || len(page.Records) != 2 || page.Total != 3 || !page.Cutoff.Equal(cutoff) || !page.Watermark.Equal(watermark) {
		t.Fatalf("page = %+v", page)
	}

	last := finishInputSnapshotPage([]string{"c"}, ports.InputSnapshotRequest{Limit: 2, Cutoff: cutoff}, 3, watermark, func(value string) string { return value })
	if !last.Complete || last.NextCursor != "" || len(last.Records) != 1 {
		t.Fatalf("last page = %+v", last)
	}
}

func TestFinishInputSnapshotPageDoesNotTruncateAtUILimit(t *testing.T) {
	records := make([]string, 501)
	for i := range records {
		records[i] = fmt.Sprintf("record-%04d", i+1)
	}
	cutoff := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	page := finishInputSnapshotPage(records, ports.InputSnapshotRequest{Limit: 500, Cutoff: cutoff}, 501, cutoff, func(value string) string { return value })
	if page.Complete || len(page.Records) != 500 || page.NextCursor != "record-0500" || page.Total != 501 {
		t.Fatalf("page count=%d complete=%v cursor=%q total=%d", len(page.Records), page.Complete, page.NextCursor, page.Total)
	}
}

func TestVerifyInputSnapshotInvariantDetectsMutation(t *testing.T) {
	expected := uint64(501)
	cutoff := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	watermark := cutoff.Add(-time.Minute)
	request := ports.InputSnapshotRequest{Cutoff: cutoff, ExpectedTotal: &expected, ExpectedWatermark: &watermark}
	if err := verifyInputSnapshotInvariant(request, 501, watermark); err != nil {
		t.Fatalf("verifyInputSnapshotInvariant(equal) error = %v", err)
	}
	if err := verifyInputSnapshotInvariant(request, 500, watermark); !errors.Is(err, ports.ErrInputSnapshotChanged) {
		t.Fatalf("verifyInputSnapshotInvariant(total changed) error = %v, want ErrInputSnapshotChanged", err)
	}
	if err := verifyInputSnapshotInvariant(request, 501, cutoff); !errors.Is(err, ports.ErrInputSnapshotChanged) {
		t.Fatalf("verifyInputSnapshotInvariant(watermark changed) error = %v, want ErrInputSnapshotChanged", err)
	}
	request.ExpectedWatermark = nil
	if err := verifyInputSnapshotInvariant(request, 501, cutoff.Add(time.Second)); !errors.Is(err, ports.ErrInputSnapshotChanged) {
		t.Fatalf("verifyInputSnapshotInvariant(after cutoff) error = %v, want ErrInputSnapshotChanged", err)
	}
}

func TestFindingEvidenceInputSnapshotClausesEnforceRuntimeTenant(t *testing.T) {
	request := ports.InputSnapshotRequest{
		TenantID:   "tenant-a",
		RuntimeIDs: []string{"runtime-a", "runtime-b"},
		Cutoff:     time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC),
	}
	clauses, args := findingEvidenceInputSnapshotScopeClauses(request)
	joined := strings.Join(clauses, " AND ")
	if !strings.Contains(joined, "input_runtime.runtime_json->>'tenant_id' = $1") {
		t.Fatalf("clauses do not enforce tenant: %s", joined)
	}
	if len(args) != 3 || args[0] != "tenant-a" || args[1] != "runtime-a" || args[2] != "runtime-b" {
		t.Fatalf("args = %#v", args)
	}
}
