package sync

import "testing"

func TestQueryRowHelpers(t *testing.T) {
	row := map[string]interface{}{
		"column_name": "ACCOUNT_ID",
		"_cq_id":      "id-1",
	}

	if got := queryRowString(row, "column_name"); got != "ACCOUNT_ID" {
		t.Fatalf("expected column_name from lowercase key, got %q", got)
	}
	if got := queryRowString(row, "COLUMN_NAME"); got != "ACCOUNT_ID" {
		t.Fatalf("expected case-insensitive lookup, got %q", got)
	}
	if got := queryRowString(row, "_CQ_ID"); got != "id-1" {
		t.Fatalf("expected underscore key lookup, got %q", got)
	}
	if value := queryRow(row, "missing"); value != nil {
		t.Fatalf("expected nil for missing key, got %#v", value)
	}
}

func TestQueryRowHelpers_UppercaseMapCompatibility(t *testing.T) {
	row := map[string]interface{}{
		"COLUMN_NAME": "REGION",
	}

	if got := queryRowString(row, "column_name"); got != "REGION" {
		t.Fatalf("expected fallback to uppercase key, got %q", got)
	}
}
