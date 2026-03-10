package graph

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGraphSnapshotDiffStore_SaveStabilizesByteSizeAtDigitBoundaries(t *testing.T) {
	store := NewGraphSnapshotDiffStore(t.TempDir())
	baseTime := time.Date(2026, 3, 10, 18, 45, 0, 0, time.UTC)

	for payloadSize := 1; payloadSize <= 4096; payloadSize++ {
		record := buildGraphSnapshotDiffStoreTestRecord(payloadSize, baseTime)
		stored, err := store.Save(record)
		if err != nil {
			t.Fatalf("Save() failed: %v", err)
		}
		if !legacyGraphSnapshotDiffByteSizeWouldDrift(*stored) {
			continue
		}

		data, err := os.ReadFile(store.pathForDiffID(stored.ID))
		if err != nil {
			t.Fatalf("ReadFile() failed: %v", err)
		}
		if got, want := stored.ByteSize, int64(len(data)); got != want {
			t.Fatalf("expected persisted byte_size=%d, got %d", want, got)
		}
		return
	}

	t.Fatal("failed to find a digit-boundary diff payload candidate")
}

func buildGraphSnapshotDiffStoreTestRecord(payloadSize int, baseTime time.Time) *GraphSnapshotDiffRecord {
	payload := strings.Repeat("x", payloadSize)
	return &GraphSnapshotDiffRecord{
		ID:          "graph_snapshot_diff:test-boundary",
		GeneratedAt: baseTime,
		From: GraphSnapshotReference{
			ID:      "graph_snapshot:before",
			BuiltAt: &baseTime,
		},
		To: GraphSnapshotReference{
			ID:      "graph_snapshot:after",
			BuiltAt: ptrGraphSnapshotTime(baseTime.Add(time.Hour)),
		},
		Summary: GraphSnapshotDiffSummary{
			NodesAdded: 1,
		},
		Diff: GraphDiff{
			NodesAdded: []*Node{
				{
					ID:   "node:test",
					Kind: NodeKindDocument,
					Name: "boundary",
					Properties: map[string]any{
						"payload": payload,
					},
				},
			},
		},
	}
}

func legacyGraphSnapshotDiffByteSizeWouldDrift(record GraphSnapshotDiffRecord) bool {
	record.ByteSize = 0
	for i := 0; i < 2; i++ {
		payload, err := json.Marshal(record)
		if err != nil {
			return false
		}
		size := int64(len(payload))
		if record.ByteSize == size {
			break
		}
		record.ByteSize = size
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return false
	}
	return record.ByteSize != int64(len(payload))
}

func ptrGraphSnapshotTime(value time.Time) *time.Time {
	return &value
}
