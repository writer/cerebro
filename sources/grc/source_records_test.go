package grc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPullFromRecordsPreservesNextCursorWithoutEvents(t *testing.T) {
	pull, err := pullFromRecords(settings{provider: "vanta", tenantID: "writer"}, familyVendor, nil, "next-page")
	if err != nil {
		t.Fatalf("pullFromRecords() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(Events) = %d, want 0", len(pull.Events))
	}
	if got := pull.NextCursor.GetOpaque(); got != "next-page" {
		t.Fatalf("NextCursor = %q, want next-page", got)
	}
}

func TestEventFromRecordScopesIDByTenantAndRuntimeConfig(t *testing.T) {
	record := grcRecord{
		Raw:    json.RawMessage(`{"id":"shared-test"}`),
		Values: map[string]any{"id": "shared-test"},
		ID:     "shared-test",
	}
	base := settings{
		provider: "vanta",
		tenantID: "writer",
		family:   familyControlTest,
		baseURL:  "https://api.vanta.com",
		clientID: "client-a",
		scope:    defaultReadScope,
	}
	first := eventFromRecord(base, familyControlTest, record)
	otherTenant := base
	otherTenant.tenantID = "acme"
	second := eventFromRecord(otherTenant, familyControlTest, record)
	otherRuntime := base
	otherRuntime.baseURL = "https://api.eu.vanta.com"
	third := eventFromRecord(otherRuntime, familyControlTest, record)
	if first.Id == second.Id || first.Id == third.Id {
		t.Fatalf("event IDs must be scoped per tenant/runtime config, got %q, %q, %q", first.Id, second.Id, third.Id)
	}
	if !strings.Contains(first.Id, "writer") || !strings.Contains(second.Id, "acme") {
		t.Fatalf("event IDs should include tenant scope, got %q and %q", first.Id, second.Id)
	}
}

func TestOccurredAtForIgnoresDeadlineOnlyFields(t *testing.T) {
	before := time.Now().UTC()
	vulnerabilityOccurredAt := occurredAtFor(familyVulnerability, map[string]any{
		"remediateByDate": "2099-01-01T00:00:00Z",
	})
	vendorOccurredAt := occurredAtFor(familyVendor, map[string]any{
		"nextSecurityReviewDueDate": "2099-01-01T00:00:00Z",
		"contractRenewalDate":       "2099-02-01T00:00:00Z",
	})
	after := time.Now().UTC()

	for name, occurredAt := range map[string]time.Time{
		"vulnerability": vulnerabilityOccurredAt,
		"vendor":        vendorOccurredAt,
	} {
		if occurredAt.Before(before.Add(-time.Second)) || occurredAt.After(after.Add(time.Second)) {
			t.Fatalf("%s occurredAt = %v, want current sync time in [%v, %v]", name, occurredAt, before, after)
		}
	}
}

func TestEventLogRecordIDFallsBackToPayloadHash(t *testing.T) {
	first := recordID(familyEventLog, map[string]any{
		"action": "vendor.review.created",
		"date":   "2026-05-03T00:00:00Z",
	}, json.RawMessage(`{"action":"vendor.review.created","date":"2026-05-03T00:00:00Z"}`))
	second := recordID(familyEventLog, map[string]any{
		"action": "vendor.review.created",
		"date":   "2026-05-04T00:00:00Z",
	}, json.RawMessage(`{"action":"vendor.review.created","date":"2026-05-04T00:00:00Z"}`))
	if first == "" || first == "vendor.review.created" {
		t.Fatalf("first event log record ID = %q, want payload hash fallback", first)
	}
	if first == second {
		t.Fatalf("event log record IDs collapsed to %q, want unique payload hashes", first)
	}
}
