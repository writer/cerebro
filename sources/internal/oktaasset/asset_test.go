package oktaasset

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestRecordTimeParsesOktaFractionalTimestamp(t *testing.T) {
	want := time.Date(2026, 4, 23, 1, 0, 0, 123_000_000, time.UTC)
	record := Record{
		Raw: []byte(`{"id":"idp-1","lastUpdated":"2026-04-23T01:00:00.123Z"}`),
		Values: map[string]any{
			"id":          "idp-1",
			"lastUpdated": "2026-04-23T01:00:00.123Z",
		},
	}

	got := record.Time("lastUpdated")
	if got == nil {
		t.Fatal("Time(lastUpdated) = nil, want parsed timestamp")
	}
	if !got.Equal(want) {
		t.Fatalf("Time(lastUpdated) = %v, want %v", *got, want)
	}

	event, err := Event(Settings{Domain: "writer.okta.com"}, KindIdentityProvider, record)
	if err != nil {
		t.Fatalf("Event() error = %v", err)
	}
	if got := event.OccurredAt.AsTime(); !got.Equal(want) {
		t.Fatalf("Event().OccurredAt = %v, want %v", got, want)
	}
	if wantID := fmt.Sprintf("okta-identity-provider-idp-1-%d", want.UnixMilli()); event.Id != wantID {
		t.Fatalf("Event().Id = %q, want %q", event.Id, wantID)
	}
}

func TestNetworkZoneAttributesSkipNullASNs(t *testing.T) {
	var record Record
	if err := json.Unmarshal([]byte(`{
		"id": "zone-1",
		"name": "Blocked networks",
		"type": "DYNAMIC",
		"status": "ACTIVE",
		"asns": [null, 64512, "", "  ", "64513"]
	}`), &record); err != nil {
		t.Fatalf("decode record: %v", err)
	}

	attrs := Attributes(Settings{Domain: "writer.okta.com"}, KindNetworkZone, record)
	if got := attrs["asn_count"]; got != "2" {
		t.Fatalf("asn_count = %q, want 2", got)
	}
	if got := attrs["asns"]; got != "64512,64513" {
		t.Fatalf("asns = %q, want 64512,64513", got)
	}
}
