package sourcecdk

import (
	"encoding/json"
	"testing"
)

type decodeRecordSample struct {
	ID  string `json:"id"`
	raw json.RawMessage
}

func TestDecodeRecordsDecodesAndCapturesRaw(t *testing.T) {
	raw := []json.RawMessage{
		json.RawMessage(`{"id":"a"}`),
		json.RawMessage(`{"id":"b"}`),
	}
	records, err := DecodeRecords(raw, "sample", func(record *decodeRecordSample, bytes json.RawMessage) {
		record.raw = append(json.RawMessage(nil), bytes...)
	})
	if err != nil {
		t.Fatalf("DecodeRecords() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d, want 2", len(records))
	}
	if records[0].ID != "a" || records[1].ID != "b" {
		t.Fatalf("decoded ids = %q,%q, want a,b", records[0].ID, records[1].ID)
	}
	if string(records[0].raw) != `{"id":"a"}` {
		t.Fatalf("captured raw = %q, want {\"id\":\"a\"}", string(records[0].raw))
	}
}

func TestDecodeRecordsNilHookAndEmptyInput(t *testing.T) {
	records, err := DecodeRecords[decodeRecordSample](nil, "sample", nil)
	if err != nil {
		t.Fatalf("DecodeRecords() error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(records) = %d, want 0", len(records))
	}
}

func TestDecodeRecordsReturnsErrorOnInvalidJSON(t *testing.T) {
	_, err := DecodeRecords[decodeRecordSample]([]json.RawMessage{json.RawMessage(`{`)}, "sample", nil)
	if err == nil {
		t.Fatal("DecodeRecords() error = nil, want non-nil")
	}
}
