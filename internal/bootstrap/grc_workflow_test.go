package bootstrap

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestGRCFindingItemsCarryWorkflowMetadata(t *testing.T) {
	now := time.Date(2026, 6, 18, 15, 30, 0, 0, time.UTC)
	findings := []*ports.FindingRecord{{
		ID:        "finding-1",
		Title:     "Privileged access without review",
		Severity:  "high",
		Status:    "OPEN",
		TenantID:  "writer",
		RuntimeID: "runtime-1",
		FindingWorkflow: ports.FindingWorkflow{
			Assignee:        "identity-team",
			DueAt:           now.Add(24 * time.Hour),
			StatusReason:    "Investigating with IAM owners",
			StatusUpdatedAt: now,
			Notes: []ports.FindingNote{{
				ID:        "note-1",
				Body:      "Escalated from GRC workbench.",
				CreatedAt: now,
			}},
			Tickets: []ports.FindingTicket{{
				URL:        "https://jira.example/browse/SEC-1",
				Name:       "SEC-1",
				ExternalID: "SEC-1",
				LinkedAt:   now,
			}},
			ExternalRefs: []ports.FindingExternalRef{{
				System:         "siem",
				Kind:           "case",
				ExternalID:     "case-1",
				URL:            "https://siem.example/cases/case-1",
				ExternalStatus: "open",
				ObservedAt:     now,
			}},
		},
	}}

	items := grcFindingItems(findings, map[string]string{"runtime-1": "okta"}, map[string]int{"finding-1": 2})
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	item := items[0]
	if item.Owner != "identity-team" || item.Assignee != "identity-team" {
		t.Fatalf("owner/assignee = %q/%q, want identity-team", item.Owner, item.Assignee)
	}
	if item.StatusReason != "Investigating with IAM owners" || item.StatusUpdatedAt == nil || !item.StatusUpdatedAt.Equal(now) {
		t.Fatalf("status metadata = %q/%v", item.StatusReason, item.StatusUpdatedAt)
	}
	if len(item.Notes) != 1 || item.Notes[0].Body != "Escalated from GRC workbench." {
		t.Fatalf("notes = %#v", item.Notes)
	}
	if len(item.Tickets) != 1 || item.Tickets[0].ExternalID != "SEC-1" {
		t.Fatalf("tickets = %#v", item.Tickets)
	}
	if len(item.ExternalRefs) != 1 || item.ExternalRefs[0].ExternalID != "case-1" {
		t.Fatalf("external refs = %#v", item.ExternalRefs)
	}
}
