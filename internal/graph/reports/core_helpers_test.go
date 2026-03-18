package reports

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBuildReportGraphSnapshotIDStableAcrossOrdering(t *testing.T) {
	builtAt := time.Date(2026, 3, 14, 15, 0, 0, 0, time.UTC)
	a := buildReportGraphSnapshotID(Metadata{
		BuiltAt:   builtAt,
		NodeCount: 10,
		EdgeCount: 20,
		Providers: []string{"gcp", "aws"},
		Accounts:  []string{"acct-b", "acct-a"},
	})
	b := buildReportGraphSnapshotID(Metadata{
		BuiltAt:   builtAt,
		NodeCount: 10,
		EdgeCount: 20,
		Providers: []string{"aws", "gcp"},
		Accounts:  []string{"acct-a", "acct-b"},
	})
	if a == "" {
		t.Fatal("expected snapshot id")
	}
	if a != b {
		t.Fatalf("expected stable snapshot id across ordering, got %q and %q", a, b)
	}
}

func TestNormalizeNodeMetadataProfileAndTypeMatching(t *testing.T) {
	profile := normalizeNodeMetadataProfile(NodeMetadataProfile{
		RequiredKeys:  []string{" owner ", "status", "owner"},
		OptionalKeys:  []string{"status", "region", "region"},
		TimestampKeys: []string{"updated_at", "updated_at"},
		EnumValues: map[string][]string{
			" status ": {" Active ", "active", "INACTIVE"},
		},
	})
	if len(profile.RequiredKeys) != 2 || profile.RequiredKeys[0] != "owner" || profile.RequiredKeys[1] != "status" {
		t.Fatalf("unexpected required keys: %#v", profile.RequiredKeys)
	}
	if len(profile.OptionalKeys) != 1 || profile.OptionalKeys[0] != "region" {
		t.Fatalf("unexpected optional keys: %#v", profile.OptionalKeys)
	}
	if len(profile.EnumValues["status"]) != 2 || profile.EnumValues["status"][0] != "active" || profile.EnumValues["status"][1] != "inactive" {
		t.Fatalf("unexpected enum values: %#v", profile.EnumValues)
	}
	if !hasNodeMetadataProfile(profile) {
		t.Fatal("expected normalized profile to be non-empty")
	}
	if !matchesPropertyType(json.Number("42"), "number") {
		t.Fatal("expected json.Number to satisfy number")
	}
	if !matchesPropertyType("2026-03-14T15:00:00Z", "timestamp") {
		t.Fatal("expected RFC3339 string to satisfy timestamp")
	}
	if matchesPropertyType("not-a-duration", "duration") {
		t.Fatal("expected invalid duration string to fail")
	}
	if !matchesPropertyType(struct{}{}, "future-schema-token") {
		t.Fatal("expected unknown schema type token to remain permissive")
	}
}

func TestReportUtilityHelpers(t *testing.T) {
	if got := firstNonEmpty("", "  ", "value", "later"); got != "value" {
		t.Fatalf("unexpected first non-empty value %q", got)
	}
	if !containsString([]string{"a", "b"}, "b") {
		t.Fatal("expected slice to contain target")
	}
	if got := sanitizeReportFileName(" ../Quarterly Report:prod.json "); got != "Quarterly-Report-prod.json" {
		t.Fatalf("unexpected sanitized filename %q", got)
	}
	counts := sortedSchemaKindCounts(map[string]int{" bucket ": 2, "role": 2, "": 3})
	if len(counts) != 3 {
		t.Fatalf("expected 3 schema counts, got %d", len(counts))
	}
	if counts[0].Kind != "<empty>" || counts[0].Count != 3 {
		t.Fatalf("unexpected leading count: %#v", counts[0])
	}
}
