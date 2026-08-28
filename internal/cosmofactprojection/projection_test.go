package cosmofactprojection

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProjectProviderFactIsBoundedClosedAndReceipted(t *testing.T) {
	raw := json.RawMessage(`{
		"record_id":"fact-7",
		"key":"coordination:risk:thread-7",
		"category":"coordination_risk",
		"source":"session:thread-7",
		"status":"active",
		"risk_reason":"provider-shaped evidence",
		"severity":"high",
		"confidence":0.875,
		"metadata":{"agent":"writer","turns":[1,2,3]}
	}`)
	projected, receipt, err := Project(raw)
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if receipt.InputDigest == receipt.OutputDigest || len(receipt.InputDigest) != 64 || len(receipt.OutputDigest) != 64 || receipt.DroppedFields != 2 {
		t.Fatalf("projection receipt = %#v", receipt)
	}
	var payload map[string]any
	if err := json.Unmarshal(projected, &payload); err != nil {
		t.Fatalf("decode projected payload: %v", err)
	}
	for _, dropped := range []string{"record_id", "metadata"} {
		if _, ok := payload[dropped]; ok {
			t.Fatalf("projected payload retained %q", dropped)
		}
	}
	decoded, err := DecodeRecord(true, raw)
	if err != nil || decoded.Values["key"] != "coordination:risk:thread-7" || string(decoded.Payload) != string(projected) {
		t.Fatalf("DecodeRecord() record=%#v err=%v", decoded, err)
	}
}

func TestProjectRejectsUnboundedOrForgedFacts(t *testing.T) {
	deep := `{"unknown":` + strings.Repeat(`{"nested":`, maxDepth) + `true` + strings.Repeat(`}`, maxDepth) + `}`
	for _, invalid := range []json.RawMessage{
		json.RawMessage(`{"key":"one","key":"two"}`),
		json.RawMessage(`{"tenant_id":"forged"}`),
		json.RawMessage(`{"key":{"nested":true}}`),
		json.RawMessage(`{"key":"` + strings.Repeat("x", maxString+1) + `"}`),
		json.RawMessage(strings.Repeat("x", maxBytes+1)),
		json.RawMessage(deep),
	} {
		if _, _, err := Project(invalid); err == nil {
			t.Fatalf("Project(%d bytes) error = nil", len(invalid))
		}
	}
}
