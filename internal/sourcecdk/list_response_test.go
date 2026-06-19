package sourcecdk

import (
	"encoding/json"
	"testing"
)

func TestDecodeListResponseDataAcceptsArray(t *testing.T) {
	records, pagination, err := DecodeListResponseData(json.RawMessage(`[{"id":"S-1"}]`), "sentinelone sites", "sites")
	if err != nil {
		t.Fatalf("DecodeListResponseData() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if pagination.NextCursor != "" {
		t.Fatalf("NextCursor = %q, want empty", pagination.NextCursor)
	}
}

func TestDecodeListResponseDataAcceptsWrappedObject(t *testing.T) {
	records, pagination, err := DecodeListResponseData(
		json.RawMessage(`{"sites":[{"id":"S-1"}],"pagination":{"nextCursor":"cursor-2","totalItems":2}}`),
		"sentinelone sites",
		"sites",
	)
	if err != nil {
		t.Fatalf("DecodeListResponseData() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if pagination.NextCursor != "cursor-2" {
		t.Fatalf("NextCursor = %q, want cursor-2", pagination.NextCursor)
	}
	if pagination.TotalItems != 2 {
		t.Fatalf("TotalItems = %d, want 2", pagination.TotalItems)
	}
}

func TestDecodeListResponseDataRejectsUnknownWrappedObject(t *testing.T) {
	_, _, err := DecodeListResponseData(json.RawMessage(`{"unexpected":[{"id":"S-1"}]}`), "sentinelone sites", "sites")
	if err == nil {
		t.Fatal("DecodeListResponseData() error = nil, want non-nil")
	}
}
