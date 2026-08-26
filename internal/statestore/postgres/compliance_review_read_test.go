package postgres

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/complianceassessment"
)

func TestComplianceCurrentChildField(t *testing.T) {
	t.Parallel()
	tests := []struct {
		table string
		want  string
		ok    bool
	}{
		{table: "compliance_work_items", want: "occurrences", ok: true},
		{table: "compliance_remediation_plans", want: "milestones", ok: true},
		{table: "compliance_reviews"},
		{table: "unknown"},
	}
	for _, test := range tests {
		t.Run(test.table, func(t *testing.T) {
			t.Parallel()
			got, ok := complianceCurrentChildField(test.table)
			if got != test.want || ok != test.ok {
				t.Fatalf("complianceCurrentChildField(%q) = %q, %v, want %q, %v", test.table, got, ok, test.want, test.ok)
			}
		})
	}
}

func BenchmarkComplianceWorkItemOccurrenceReadMaterialization(b *testing.B) {
	fullBody, currentBody, childBodies := benchmarkComplianceWorkItemBodies(b, 256)
	totalChildBytes := 0
	for _, body := range childBodies {
		totalChildBytes += len(body)
	}

	b.Run("duplicated_current_jsonb", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(fullBody) + totalChildBytes))
		b.ReportMetric(float64(len(fullBody)), "current-jsonb-bytes")
		for range b.N {
			var projection ComplianceWorkItemProjection
			currentRow := append([]byte(nil), fullBody...)
			if err := json.Unmarshal(currentRow, &projection.Item); err != nil {
				b.Fatal(err)
			}
			buffered := make([][]byte, 0)
			for _, body := range childBodies {
				buffered = append(buffered, append([]byte(nil), body...))
			}
			projection.Occurrences = make([]complianceassessment.WorkOccurrence, 0, len(buffered))
			for _, body := range buffered {
				var occurrence complianceassessment.WorkOccurrence
				if err := json.Unmarshal(body, &occurrence); err != nil {
					b.Fatal(err)
				}
				projection.Occurrences = append(projection.Occurrences, occurrence)
			}
			projection.Item.Occurrences = append([]complianceassessment.WorkOccurrence(nil), projection.Occurrences...)
			runtime.KeepAlive(projection)
		}
	})

	b.Run("canonical_child_stream", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(currentBody) + totalChildBytes))
		b.ReportMetric(float64(len(currentBody)), "current-jsonb-bytes")
		for range b.N {
			var projection ComplianceWorkItemProjection
			currentRow := append([]byte(nil), currentBody...)
			if err := json.Unmarshal(currentRow, &projection.Item); err != nil {
				b.Fatal(err)
			}
			for _, body := range childBodies {
				rowBody := append([]byte(nil), body...)
				var occurrence complianceassessment.WorkOccurrence
				if err := json.Unmarshal(rowBody, &occurrence); err != nil {
					b.Fatal(err)
				}
				projection.Occurrences = append(projection.Occurrences, occurrence)
			}
			projection.Item.Occurrences = append([]complianceassessment.WorkOccurrence(nil), projection.Occurrences...)
			runtime.KeepAlive(projection)
		}
	})
}

func benchmarkComplianceWorkItemBodies(b *testing.B, childCount int) ([]byte, []byte, [][]byte) {
	b.Helper()
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	item := complianceassessment.WorkItem{
		ID: "work-item", FingerprintVersion: "v1", Fingerprint: "sha256:fingerprint",
		Basis: complianceassessment.WorkFingerprintInput{
			TenantID: "tenant-a", ProgramID: "program-a", ScopeRevisionID: "scope-a",
			ControlID: "control-a", ObjectiveID: "objective-a", Kind: complianceassessment.WorkRemediateFinding,
			SubjectID: "subject-a", Reason: complianceassessment.ReasonActiveFinding, SourceID: "source-a",
		},
		State: complianceassessment.WorkOpen, OwnerID: "owner-a", DueAt: now.Add(24 * time.Hour),
		Priority: "high", Version: uint64(childCount), UpdatedAt: now,
	}
	childBodies := make([][]byte, 0, childCount)
	for index := range childCount {
		occurrence := complianceassessment.WorkOccurrence{
			ID: fmt.Sprintf("occurrence-%04d", index), WorkItemID: item.ID,
			AssessmentRunID: fmt.Sprintf("assessment-%04d", index), ObjectiveResultID: fmt.Sprintf("result-%04d", index),
			AutomatedResultHash: fmt.Sprintf("sha256:%064d", index),
			EvidenceIDs:         []string{fmt.Sprintf("evidence-%04d-a", index), fmt.Sprintf("evidence-%04d-b", index)},
			FindingIDs:          []string{fmt.Sprintf("finding-%04d-a", index), fmt.Sprintf("finding-%04d-b", index)},
			OccurredAt:          now.Add(time.Duration(index) * time.Minute),
			OccurrenceHash:      fmt.Sprintf("sha256:%064d", index+1),
		}
		item.Occurrences = append(item.Occurrences, occurrence)
		body, err := json.Marshal(occurrence)
		if err != nil {
			b.Fatal(err)
		}
		childBodies = append(childBodies, body)
	}
	fullBody, err := json.Marshal(item)
	if err != nil {
		b.Fatal(err)
	}
	var currentProjection map[string]json.RawMessage
	if err := json.Unmarshal(fullBody, &currentProjection); err != nil {
		b.Fatal(err)
	}
	delete(currentProjection, "occurrences")
	currentBody, err := json.Marshal(currentProjection)
	if err != nil {
		b.Fatal(err)
	}
	return fullBody, currentBody, childBodies
}
