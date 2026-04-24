package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestUpsertFindingRejectsNilFinding(t *testing.T) {
	store := &Store{}
	if _, err := store.UpsertFinding(context.Background(), nil); err == nil {
		t.Fatal("UpsertFinding() error = nil, want non-nil")
	}
}

func TestUpsertFindingRejectsMissingRuleID(t *testing.T) {
	store := &Store{}
	_, err := store.UpsertFinding(context.Background(), &ports.FindingRecord{
		ID:              "finding-1",
		Fingerprint:     "fingerprint-1",
		TenantID:        "writer",
		RuntimeID:       "writer-okta-audit",
		Title:           "Okta Policy Rule Lifecycle Tampering",
		Severity:        "HIGH",
		Status:          "open",
		Summary:         "admin@writer.com performed policy.rule.update on pol-1",
		FirstObservedAt: time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
		LastObservedAt:  time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("UpsertFinding() error = nil, want non-nil")
	}
}

func TestUpsertFindingRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	_, err := store.UpsertFinding(context.Background(), &ports.FindingRecord{
		ID:              "finding-1",
		Fingerprint:     "fingerprint-1",
		TenantID:        "writer",
		RuntimeID:       "writer-okta-audit",
		RuleID:          "identity-okta-policy-rule-lifecycle-tampering",
		Title:           "Okta Policy Rule Lifecycle Tampering",
		Severity:        "HIGH",
		Status:          "open",
		Summary:         "admin@writer.com performed policy.rule.update on pol-1",
		FirstObservedAt: time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
		LastObservedAt:  time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("UpsertFinding() error = nil, want non-nil")
	}
}

func TestListFindingsRejectsMissingRuntimeID(t *testing.T) {
	store := &Store{}
	if _, err := store.ListFindings(context.Background(), ports.ListFindingsRequest{}); err == nil {
		t.Fatal("ListFindings() error = nil, want non-nil")
	}
}

func TestListFindingsRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	if _, err := store.ListFindings(context.Background(), ports.ListFindingsRequest{RuntimeID: "writer-okta-audit"}); err == nil {
		t.Fatal("ListFindings() error = nil, want non-nil")
	}
}

func TestFindingListQueryIncludesOptionalFilters(t *testing.T) {
	query, args, err := findingListQuery(ports.ListFindingsRequest{
		RuntimeID:   "writer-okta-audit",
		FindingID:   "finding-1",
		RuleID:      "identity-okta-policy-rule-lifecycle-tampering",
		Severity:    "HIGH",
		Status:      "open",
		ResourceURN: "urn:cerebro:writer:okta_resource:policyrule:pol-1",
		EventID:     "okta-audit-2",
		Limit:       25,
	})
	if err != nil {
		t.Fatalf("findingListQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"runtime_id = $1",
		"id = $2",
		"rule_id = $3",
		"severity = $4",
		"status = $5",
		"resource_urns_json @> $6::jsonb",
		"event_ids_json @> $7::jsonb",
		"LIMIT $8",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingListQuery() query missing %q: %s", fragment, query)
		}
	}
	if got := len(args); got != 8 {
		t.Fatalf("len(findingListQuery().args) = %d, want 8", got)
	}
	if got := args[0]; got != "writer-okta-audit" {
		t.Fatalf("findingListQuery().args[0] = %#v, want writer-okta-audit", got)
	}
	if got := args[5]; got != `["urn:cerebro:writer:okta_resource:policyrule:pol-1"]` {
		t.Fatalf("findingListQuery().args[5] = %#v, want resource urn array json", got)
	}
	if got := args[6]; got != `["okta-audit-2"]` {
		t.Fatalf("findingListQuery().args[6] = %#v, want event id array json", got)
	}
	if got := args[7]; got != int64(25) {
		t.Fatalf("findingListQuery().args[7] = %#v, want 25", got)
	}
}
