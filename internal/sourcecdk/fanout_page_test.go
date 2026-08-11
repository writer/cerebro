package sourcecdk

import (
	"reflect"
	"testing"
)

func TestPageFanoutRecordsBoundsChildrenAndPreservesParentCursor(t *testing.T) {
	parents := map[string]struct {
		id   string
		next string
	}{
		"":              {id: "parent-1", next: "provider-next"},
		"provider-next": {id: "parent-2"},
	}
	records := map[string][]string{
		"parent-1": {"record-3", "record-1", "record-2"},
		"parent-2": {"record-4"},
	}
	resolve := func(cursor string) (string, string, error) {
		parent := parents[cursor]
		return parent.id, parent.next, nil
	}
	read := func(parentID string) ([]string, error) { return records[parentID], nil }
	identity := func(record string) string { return record }

	first, cursor, err := PageFanoutRecords("", "test:", 2, "", resolve, read, identity)
	if err != nil {
		t.Fatalf("PageFanoutRecords(first) error = %v", err)
	}
	if !reflect.DeepEqual(first, []string{"record-1", "record-2"}) || cursor == "" {
		t.Fatalf("first = %v, cursor = %q", first, cursor)
	}
	second, cursor, err := PageFanoutRecords(cursor, "test:", 2, "", resolve, read, identity)
	if err != nil {
		t.Fatalf("PageFanoutRecords(second) error = %v", err)
	}
	if !reflect.DeepEqual(second, []string{"record-3"}) || cursor != "provider-next" {
		t.Fatalf("second = %v, cursor = %q", second, cursor)
	}
	third, cursor, err := PageFanoutRecords(cursor, "test:", 2, "", resolve, read, identity)
	if err != nil {
		t.Fatalf("PageFanoutRecords(third) error = %v", err)
	}
	if !reflect.DeepEqual(third, []string{"record-4"}) || cursor != "" {
		t.Fatalf("third = %v, cursor = %q", third, cursor)
	}
}

func TestPageFanoutRecordsRejectsDuplicateIdentity(t *testing.T) {
	_, _, err := PageFanoutRecords("", "test:", 2, "parent", nil,
		func(string) ([]string, error) { return []string{"duplicate", "duplicate"}, nil },
		func(record string) string { return record })
	if err == nil {
		t.Fatal("PageFanoutRecords() error = nil, want duplicate identity rejection")
	}
}
