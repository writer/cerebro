package sourcecdk

import (
	"encoding/json"
	"testing"
)

func TestPayloadOverlayMergesFieldsWithoutBase(t *testing.T) {
	got, err := NewPayloadOverlay().Set("domain", "writer.com").MergeRawJSON(nil)
	if err != nil {
		t.Fatalf("MergeRawJSON() error = %v", err)
	}
	if string(got) != `{"domain":"writer.com"}` {
		t.Fatalf("MergeRawJSON() = %s, want {\"domain\":\"writer.com\"}", got)
	}
}

func TestPayloadOverlayOverlaysAndOverwritesRawFields(t *testing.T) {
	raw := json.RawMessage(`{"id":"1001","domain":"stale"}`)
	got, err := NewPayloadOverlay().
		Set("domain", "writer.com").
		Set("group_key", "security@writer.com").
		MergeRawJSON(raw)
	if err != nil {
		t.Fatalf("MergeRawJSON() error = %v", err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("Unmarshal(%s) error = %v", got, err)
	}
	for key, want := range map[string]string{
		"id":        "1001",
		"domain":    "writer.com",
		"group_key": "security@writer.com",
	} {
		if decoded[key] != want {
			t.Fatalf("payload[%q] = %q, want %q", key, decoded[key], want)
		}
	}
}

func TestPayloadOverlayReturnsErrorForInvalidRaw(t *testing.T) {
	if _, err := NewPayloadOverlay().MergeRawJSON(json.RawMessage(`not-json`)); err == nil {
		t.Fatal("MergeRawJSON() error = nil, want decode error")
	}
}
