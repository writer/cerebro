package oktaasset

import (
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
