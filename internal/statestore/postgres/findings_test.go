package postgres

import (
	"context"
	"database/sql"
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

func TestUpdateFindingDueDateRejectsMissingDueDate(t *testing.T) {
	store := &Store{}
	if _, err := store.UpdateFindingDueDate(context.Background(), ports.FindingDueDateUpdate{FindingID: "finding-1"}); err == nil {
		t.Fatal("UpdateFindingDueDate() error = nil, want non-nil")
	}
}

func TestAddFindingNoteRejectsEmptyNote(t *testing.T) {
	store := &Store{}
	if _, err := store.AddFindingNote(context.Background(), ports.FindingNoteCreate{FindingID: "finding-1"}); err == nil {
		t.Fatal("AddFindingNote() error = nil, want non-nil")
	}
}

func TestFindingListQueryIncludesOptionalFilters(t *testing.T) {
	query, args, err := findingListQuery(ports.ListFindingsRequest{
		RuntimeID:   "writer-okta-audit",
		FindingID:   "finding-1",
		RuleID:      "identity-okta-policy-rule-lifecycle-tampering",
		Severity:    "HIGH",
		Status:      "open",
		PolicyID:    "pol-1",
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
		"policy_id = $6",
		"resource_urns_json @> $7::jsonb",
		"event_ids_json @> $8::jsonb",
		"LIMIT $9",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingListQuery() query missing %q: %s", fragment, query)
		}
	}
	if got := len(args); got != 9 {
		t.Fatalf("len(findingListQuery().args) = %d, want 9", got)
	}
	if got := args[0]; got != "writer-okta-audit" {
		t.Fatalf("findingListQuery().args[0] = %#v, want writer-okta-audit", got)
	}
	if got := args[5]; got != "pol-1" {
		t.Fatalf("findingListQuery().args[5] = %#v, want pol-1", got)
	}
	if got := args[6]; got != `["urn:cerebro:writer:okta_resource:policyrule:pol-1"]` {
		t.Fatalf("findingListQuery().args[6] = %#v, want resource urn array json", got)
	}
	if got := args[7]; got != `["okta-audit-2"]` {
		t.Fatalf("findingListQuery().args[7] = %#v, want event id array json", got)
	}
	if got := args[8]; got != int64(25) {
		t.Fatalf("findingListQuery().args[8] = %#v, want 25", got)
	}
}

func TestFindingRowRecordDecodesCheckAndControlMetadata(t *testing.T) {
	record, err := (findingRow{
		ID:                    "finding-1",
		Fingerprint:           "fingerprint-1",
		TenantID:              "writer",
		RuntimeID:             "writer-okta-audit",
		RuleID:                "identity-okta-policy-rule-lifecycle-tampering",
		Title:                 "Okta Policy Rule Lifecycle Tampering",
		Severity:              "HIGH",
		Status:                "open",
		Summary:               "admin@writer.com performed policy.rule.update on pol-1",
		ResourceURNsJSON:      `["urn:cerebro:writer:okta_resource:policyrule:pol-1"]`,
		EventIDsJSON:          `["okta-audit-2"]`,
		ObservedPolicyIDsJSON: `["pol-1"]`,
		ControlRefsJSON:       `[{"framework_name":"SOC 2","control_id":"CC6.2"},{"framework_name":"ISO 27001:2022","control_id":"A.8.9"}]`,
		PolicyID:              "pol-1",
		PolicyName:            "pol-1",
		CheckID:               "identity-okta-policy-rule-lifecycle-tampering-30d",
		CheckName:             "Okta Policy Rule Lifecycle Tampering (30 days)",
		AttributesJSON:        `{"primary_resource_urn":"urn:cerebro:writer:okta_resource:policyrule:pol-1"}`,
		findingWorkflowRow: findingWorkflowRow{
			NotesJSON: `[{"id":"note-1","body":"Escalate to identity engineering.","created_at":"2026-05-01T11:00:00Z"}]`,
			DueAt:     sql.NullTime{Time: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC), Valid: true},
		},
		FirstObservedAt: time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
		LastObservedAt:  time.Date(2026, 4, 23, 12, 1, 0, 0, time.UTC),
	}).record()
	if err != nil {
		t.Fatalf("findingRow.record() error = %v", err)
	}
	if got := record.CheckID; got != "identity-okta-policy-rule-lifecycle-tampering-30d" {
		t.Fatalf("findingRow.record().CheckID = %q, want identity-okta-policy-rule-lifecycle-tampering-30d", got)
	}
	if got := record.CheckName; got != "Okta Policy Rule Lifecycle Tampering (30 days)" {
		t.Fatalf("findingRow.record().CheckName = %q, want check name", got)
	}
	if got := len(record.ControlRefs); got != 2 {
		t.Fatalf("len(findingRow.record().ControlRefs) = %d, want 2", got)
	}
	if got := record.ControlRefs[0].FrameworkName; got != "SOC 2" {
		t.Fatalf("findingRow.record().ControlRefs[0].FrameworkName = %q, want SOC 2", got)
	}
	if got := record.DueAt; !got.Equal(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("findingRow.record().DueAt = %v, want 2026-05-01 12:00:00 +0000 UTC", got)
	}
	if got := len(record.Notes); got != 1 {
		t.Fatalf("len(findingRow.record().Notes) = %d, want 1", got)
	}
	if got := record.Notes[0].Body; got != "Escalate to identity engineering." {
		t.Fatalf("findingRow.record().Notes[0].Body = %q, want note body", got)
	}
}
