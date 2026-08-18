package okta

import (
	"bytes"
	"testing"

	"github.com/writer/cerebro/internal/primitives"
)

func TestThreatInsightEventIdentityBindsCompleteDurableMaterial(t *testing.T) {
	settings := settings{domain: "example.okta.test"}
	base := threatInsightRecord{
		Action:       "block",
		ExcludeZones: []string{"zone-b", "zone-a"},
		Created:      "2026-08-12T00:00:00Z",
		LastUpdated:  "2026-08-12T01:00:00.123456Z",
	}
	first := mustThreatInsightEvent(t, settings, base)
	same := mustThreatInsightEvent(t, settings, threatInsightRecord{
		Action:       base.Action,
		ExcludeZones: []string{"zone-a", "zone-b"},
		Created:      base.Created,
		LastUpdated:  base.LastUpdated,
	})
	changedTime := mustThreatInsightEvent(t, settings, threatInsightRecord{
		Action:       base.Action,
		ExcludeZones: base.ExcludeZones,
		Created:      base.Created,
		LastUpdated:  "2026-08-13T01:00:00.123456Z",
	})
	changedAction := mustThreatInsightEvent(t, settings, threatInsightRecord{
		Action:       "none",
		ExcludeZones: base.ExcludeZones,
		Created:      base.Created,
		LastUpdated:  base.LastUpdated,
	})

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

func mustThreatInsightEvent(t *testing.T, settings settings, record threatInsightRecord) *primitives.Event {
	t.Helper()
	event, err := threatInsightEvent(settings, record)
	if err != nil {
		t.Fatal(err)
	}
	return event
}
