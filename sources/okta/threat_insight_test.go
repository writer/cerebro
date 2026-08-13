package okta

import (
	"bytes"
	"testing"
)

func TestThreatInsightEventIdentityBindsCompleteDurableMaterial(t *testing.T) {
	settings := settings{domain: "example.okta.test"}
	base := threatInsightRecord{
		Action:       "block",
		ExcludeZones: []string{"zone-b", "zone-a"},
		Created:      "2026-08-12T00:00:00Z",
		LastUpdated:  "2026-08-12T01:00:00.123456Z",
	}
	first, err := threatInsightEvent(settings, base)
	if err != nil {
		t.Fatal(err)
	}
	same, err := threatInsightEvent(settings, threatInsightRecord{
		Action:       base.Action,
		ExcludeZones: []string{"zone-a", "zone-b"},
		Created:      base.Created,
		LastUpdated:  base.LastUpdated,
	})
	if err != nil {
		t.Fatal(err)
	}
	changedTime, err := threatInsightEvent(settings, threatInsightRecord{
		Action:       base.Action,
		ExcludeZones: base.ExcludeZones,
		Created:      base.Created,
		LastUpdated:  "2026-08-13T01:00:00.123456Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	changedAction, err := threatInsightEvent(settings, threatInsightRecord{
		Action:       "none",
		ExcludeZones: base.ExcludeZones,
		Created:      base.Created,
		LastUpdated:  base.LastUpdated,
	})
	if err != nil {
		t.Fatal(err)
	}

	if first.Id != same.Id || !bytes.Equal(first.Payload, same.Payload) || first.OccurredAt.AsTime() != same.OccurredAt.AsTime() {
		t.Fatalf("identical durable material was not idempotent: first=%#v same=%#v", first, same)
	}
	if first.Id == changedTime.Id {
		t.Fatalf("changed occurred_at reused immutable event ID %q", first.Id)
	}
	if first.Id == changedAction.Id {
		t.Fatalf("changed payload reused immutable event ID %q", first.Id)
	}
	if first.Attributes["resource_id"] != changedAction.Attributes["resource_id"] {
		t.Fatalf("stable entity identity changed: %#v != %#v", first.Attributes, changedAction.Attributes)
	}
	if got := first.OccurredAt.AsTime().Nanosecond(); got%1_000_000 != 0 {
		t.Fatalf("occurred_at nanoseconds = %d, want millisecond normalization", got)
	}
}

func TestThreatInsightEventMissingTimestampsFailsClosed(t *testing.T) {
	settings := settings{domain: "example.okta.test"}
	for _, record := range []threatInsightRecord{
		{Action: "block"},
		{Action: "block", Created: "1970-01-01T00:00:00Z"},
		{Action: "block", LastUpdated: "invalid", Created: "invalid"},
	} {
		if event, err := threatInsightEvent(settings, record); err == nil {
			t.Fatalf("threatInsightEvent(%#v) = %#v, want timestamp error", record, event)
		}
	}
}
