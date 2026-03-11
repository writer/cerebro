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

func TestDecodeExistingHashes_CaseInsensitiveKeys(t *testing.T) {
	rows := []map[string]interface{}{
		{"_CQ_ID": "id-1", "_CQ_HASH": "hash-1"},
		{"_cq_id": "id-2", "_cq_hash": "hash-2"},
		{"_cq_id": "", "_cq_hash": "ignored"},
		{"_cq_hash": "missing-id"},
	}

	decoded := decodeExistingHashes(rows)
	if len(decoded) != 2 {
		t.Fatalf("expected 2 decoded hashes, got %d", len(decoded))
	}
	if decoded["id-1"] != "hash-1" {
		t.Fatalf("expected hash-1 for id-1, got %q", decoded["id-1"])
	}
	if decoded["id-2"] != "hash-2" {
		t.Fatalf("expected hash-2 for id-2, got %q", decoded["id-2"])
	}
}

func TestQueryRowHelpers_BuildsLookupCache(t *testing.T) {
	row := map[string]interface{}{
		"COLUMN_NAME": "REGION",
		"_CQ_ID":      "id-1",
	}

	if got := queryRowString(row, "column_name"); got != "REGION" {
		t.Fatalf("expected case-insensitive lookup to resolve, got %q", got)
	}

	cache, ok := row[queryRowLookupCacheKey].(map[string]string)
	if !ok {
		t.Fatalf("expected row lookup cache to be stored on first lookup, got %#v", row[queryRowLookupCacheKey])
	}
	if cache["column_name"] != "COLUMN_NAME" {
		t.Fatalf("expected cache to map normalized key to source key, got %#v", cache)
	}
	if cache["_cq_id"] != "_CQ_ID" {
		t.Fatalf("expected cache to include _CQ_ID mapping, got %#v", cache)
	}

	if got := queryRowString(row, "_cq_id"); got != "id-1" {
		t.Fatalf("expected cached lookup for _cq_id, got %q", got)
	}
}
