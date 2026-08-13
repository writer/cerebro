package okta

import "testing"

func TestThreatInsightEventUsesLogicalStateIdentity(t *testing.T) {
	settings := settings{domain: "example.okta.test"}
	first, err := threatInsightEvent(settings, threatInsightRecord{
		Action:       "block",
		ExcludeZones: []string{"zone-b", "zone-a"},
		Created:      "2026-08-12T00:00:00Z",
		LastUpdated:  "2026-08-12T01:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	sameState, err := threatInsightEvent(settings, threatInsightRecord{
		Action:       "block",
		ExcludeZones: []string{"zone-a", "zone-b"},
		Created:      "2026-08-12T00:00:00Z",
		LastUpdated:  "2026-08-13T01:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	changedState, err := threatInsightEvent(settings, threatInsightRecord{
		Action:       "none",
		ExcludeZones: []string{"zone-a", "zone-b"},
		Created:      "2026-08-12T00:00:00Z",
		LastUpdated:  "2026-08-13T01:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	changedZones, err := threatInsightEvent(settings, threatInsightRecord{
		Action:       "block",
		ExcludeZones: []string{"zone-a", "zone-c"},
		Created:      "2026-08-12T00:00:00Z",
		LastUpdated:  "2026-08-13T01:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}

	if first.Id != sameState.Id {
		t.Fatalf("unchanged logical state IDs differ: %q != %q", first.Id, sameState.Id)
	}
	if first.Id == changedState.Id {
		t.Fatalf("changed logical state reused event ID %q", first.Id)
	}
	if first.Id == changedZones.Id {
		t.Fatalf("changed exclusion zones reused event ID %q", first.Id)
	}
	if first.Attributes["resource_id"] != changedState.Attributes["resource_id"] {
		t.Fatalf("stable entity identity changed: %#v != %#v", first.Attributes, changedState.Attributes)
	}
	if len(first.Id) != len("okta-threat-insight-sha256-")+64 {
		t.Fatalf("event ID = %q, want bounded SHA-256 identity", first.Id)
	}
}
