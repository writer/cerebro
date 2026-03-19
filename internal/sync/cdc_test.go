package sync

import (
	"testing"
	"time"
)

func TestBuildRowLookupSkipsMissingIDs(t *testing.T) {
	rows := []map[string]interface{}{
		{"_cq_id": "row-1", "name": "first"},
		{"_cq_id": "", "name": "empty"},
		{"name": "missing"},
		{"_cq_id": "row-2", "name": "second"},
	}

	lookup := buildRowLookup(rows)
	if len(lookup) != 2 {
		t.Fatalf("expected 2 rows in lookup, got %d", len(lookup))
	}
	if lookup["row-1"]["name"] != "first" {
		t.Fatalf("unexpected lookup value for row-1: %#v", lookup["row-1"])
	}
	if _, ok := lookup[""]; ok {
		t.Fatalf("did not expect empty id in lookup")
	}
}

func TestBuildCDCEventsFromChangesIncludesPayloadAndFallbackScope(t *testing.T) {
	syncTime := time.Date(2026, 3, 12, 16, 0, 0, 0, time.UTC)
	rows := map[string]map[string]interface{}{
		"row-added": {
			"_cq_id":     "row-added",
			"_cq_hash":   "old-hash",
			"name":       "added",
			"account_id": "acct-row",
			"region":     "us-west-2",
		},
		"row-modified": {
			"_cq_id":   "row-modified",
			"_cq_hash": "old-hash",
			"name":     "modified",
			"project":  "project-row",
			"location": "europe-west1",
		},
	}

	events := buildCDCEventsFromChanges(
		"AWS_SAMPLE_TABLE",
		"aws",
		"",
		"",
		&ChangeSet{
			Added:    []string{"row-added"},
			Modified: []string{"row-modified"},
			Removed:  []string{"row-removed"},
		},
		rows,
		syncTime,
		func(row map[string]interface{}) string { return row["name"].(string) + "-hash" },
	)

	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	added := events[0]
	if added.ChangeType != cdcChangeAdded {
		t.Fatalf("expected added change type, got %q", added.ChangeType)
	}
	if added.AccountID != "acct-row" || added.Region != "us-west-2" {
		t.Fatalf("expected fallback account/region from payload, got account=%q region=%q", added.AccountID, added.Region)
	}
	payload, ok := added.Payload.(map[string]interface{})
	if !ok {
		t.Fatalf("expected payload map, got %T", added.Payload)
	}
	if _, ok := payload["_cq_id"]; ok {
		t.Fatalf("expected payload to exclude _cq_id, got %#v", payload)
	}
	if _, ok := payload["_cq_hash"]; ok {
		t.Fatalf("expected payload to exclude _cq_hash, got %#v", payload)
	}
	if added.PayloadHash != "added-hash" {
		t.Fatalf("expected payload hash to use hash func, got %q", added.PayloadHash)
	}
	if !added.EventTime.Equal(syncTime) {
		t.Fatalf("expected sync time %s, got %s", syncTime, added.EventTime)
	}

	modified := events[1]
	if modified.ChangeType != cdcChangeModified {
		t.Fatalf("expected modified change type, got %q", modified.ChangeType)
	}
	if modified.AccountID != "project-row" || modified.Region != "europe-west1" {
		t.Fatalf("expected project/location fallback for modified row, got account=%q region=%q", modified.AccountID, modified.Region)
	}

	removed := events[2]
	if removed.ChangeType != cdcChangeRemoved {
		t.Fatalf("expected removed change type, got %q", removed.ChangeType)
	}
	if removed.Payload != nil {
		t.Fatalf("expected removed payload to be nil, got %#v", removed.Payload)
	}
}

func TestBuildCDCEventsFromChangesHandlesNilChanges(t *testing.T) {
	if events := buildCDCEventsFromChanges("TABLE", "aws", "us-east-1", "acct", nil, nil, time.Time{}, nil); events != nil {
		t.Fatalf("expected nil events for nil changes, got %#v", events)
	}
}

func TestExtractStringSupportsMultipleRepresentations(t *testing.T) {
	row := map[string]interface{}{
		"primary": []byte("bytes"),
		"empty":   "",
		"other":   "value",
	}

	if got := extractString(row, "missing", "primary"); got != "bytes" {
		t.Fatalf("expected bytes fallback, got %q", got)
	}
	if got := extractString(row, "empty", "other"); got != "value" {
		t.Fatalf("expected next non-empty string, got %q", got)
	}
	if got := extractString(row, "missing"); got != "" {
		t.Fatalf("expected empty string for missing keys, got %q", got)
	}
}
