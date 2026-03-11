package sync

import (
	"reflect"
	"sort"
	"testing"
)

func TestDetectRowChanges_NoChurnOnIdenticalRows(t *testing.T) {
	existing := map[string]string{"id-1": "hash-1", "id-2": "hash-2"}
	newRows := map[string]string{"id-1": "hash-1", "id-2": "hash-2"}

	changes := detectRowChanges(existing, newRows, false)

	assertIDs(t, changes.Added, nil)
	assertIDs(t, changes.Modified, nil)
	assertIDs(t, changes.Removed, nil)
}

func TestDetectRowChanges_FullSyncDetectsDeletion(t *testing.T) {
	existing := map[string]string{"id-1": "hash-1", "id-2": "hash-2"}
	newRows := map[string]string{"id-1": "hash-1"}

	changes := detectRowChanges(existing, newRows, false)

	assertIDs(t, changes.Added, nil)
	assertIDs(t, changes.Modified, nil)
	assertIDs(t, changes.Removed, []string{"id-2"})
}

func TestDetectRowChanges_IncrementalIgnoresMissingExistingRows(t *testing.T) {
	existing := map[string]string{"id-1": "hash-1", "id-2": "hash-2"}
	newRows := map[string]string{"id-1": "hash-1"}

	changes := detectRowChanges(existing, newRows, true)

	assertIDs(t, changes.Added, nil)
	assertIDs(t, changes.Modified, nil)
	assertIDs(t, changes.Removed, nil)
}

func TestDetectRowChanges_IncrementalDetectsAddedAndModified(t *testing.T) {
	existing := map[string]string{"id-1": "hash-1", "id-2": "hash-2"}
	newRows := map[string]string{"id-1": "hash-1-updated", "id-3": "hash-3"}

	changes := detectRowChanges(existing, newRows, true)

	assertIDs(t, changes.Added, []string{"id-3"})
	assertIDs(t, changes.Modified, []string{"id-1"})
	assertIDs(t, changes.Removed, nil)
}

func TestBuildRowHashes_DeduplicatesAndSkipsInvalidRows(t *testing.T) {
	rows := []map[string]interface{}{
		{"_cq_id": "id-1", "name": "original"},
		{"_cq_id": "id-1", "name": "latest"},
		{"_cq_id": 42, "name": "invalid-id-type"},
		{"name": "missing-id"},
	}

	hashes := buildRowHashes(rows, hashRowContent)

	if len(hashes) != 1 {
		t.Fatalf("expected 1 hash entry, got %d", len(hashes))
	}
	if _, ok := hashes["id-1"]; !ok {
		t.Fatalf("expected id-1 hash to be present")
	}
}

func TestDedupeRowsByID_UsesLatestAndSkipsInvalid(t *testing.T) {
	rows := []map[string]interface{}{
		{"_cq_id": "id-1", "value": "first"},
		{"_cq_id": "id-2", "value": "only"},
		{"_cq_id": "id-1", "value": "latest"},
		{"_cq_id": 12, "value": "invalid"},
	}

	deduped := dedupeRowsByID(rows)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 deduped rows, got %d", len(deduped))
	}

	byID := make(map[string]string, len(deduped))
	for _, row := range deduped {
		id, _ := row["_cq_id"].(string)
		byID[id], _ = row["value"].(string)
	}

	if got := byID["id-1"]; got != "latest" {
		t.Fatalf("expected id-1 latest row, got %q", got)
	}
	if got := byID["id-2"]; got != "only" {
		t.Fatalf("expected id-2 row, got %q", got)
	}
}

func assertIDs(t *testing.T, got []string, want []string) {
	t.Helper()
	sortedGot := append([]string(nil), got...)
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedGot)
	sort.Strings(sortedWant)
	if !reflect.DeepEqual(sortedGot, sortedWant) {
		t.Fatalf("unexpected ids: got %v, want %v", sortedGot, sortedWant)
	}
}
