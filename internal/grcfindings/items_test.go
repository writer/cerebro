package grcfindings

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestFindingItemsNormalizeRiskInboxRows(t *testing.T) {
	dueAt := time.Now().UTC().Add(48 * time.Hour)
	statusUpdatedAt := time.Now().UTC().Add(-time.Hour)
	findings := []*ports.FindingRecord{{
		ID:           "finding-1",
		TenantID:     "tenant-1",
		RuntimeID:    "runtime-1",
		RuleID:       "rule-1",
		Title:        "Privileged access needs review",
		Severity:     "high",
		Status:       "open",
		Summary:      "Privileged access lacks review evidence.",
		ResourceURNs: []string{"urn:cerebro:tenant-1:identity:user-1"},
		PolicyID:     "policy-1",
		PolicyName:   "Access review",
		ControlRefs:  []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
		FindingRisk: ports.FindingRisk{
			RiskScore:        72,
			LikelihoodScore:  70,
			ImpactScore:      80,
			ConfidenceScore:  90,
			LikelihoodLevel:  "high",
			ImpactLevel:      "high",
			RiskReasons:      []string{"privileged access"},
			RiskModelVersion: "risk-v1",
		},
		FindingWorkflow: ports.FindingWorkflow{
			Assignee:        "security-owner",
			DueAt:           dueAt,
			StatusReason:    "triaged",
			StatusUpdatedAt: statusUpdatedAt,
			Notes:           []ports.FindingNote{{ID: "note-1", Body: "Owner confirmed.", CreatedAt: statusUpdatedAt}},
		},
	}}
	items := FindingItems(findings, map[string]string{"runtime-1": "okta"}, map[string]int{"finding-1": 3})
	if len(items) != 1 {
		t.Fatalf("len(FindingItems) = %d, want 1", len(items))
	}
	item := items[0]
	if item.Severity != "HIGH" || item.Status != "OPEN" {
		t.Fatalf("normalized severity/status = %q/%q, want HIGH/OPEN", item.Severity, item.Status)
	}
	if item.SourceID != "okta" || item.Entity != "urn:cerebro:tenant-1:identity:user-1" {
		t.Fatalf("source/entity = %q/%q", item.SourceID, item.Entity)
	}
	if item.RiskScore != 72 || item.RiskModel != "risk-v1" {
		t.Fatalf("risk fields = score %d model %q", item.RiskScore, item.RiskModel)
	}
	if item.Owner != "security-owner" || item.SLAStatus != "due_soon" || item.EvidenceCount != 3 {
		t.Fatalf("workflow fields owner=%q sla=%q evidence=%d", item.Owner, item.SLAStatus, item.EvidenceCount)
	}
	if item.DueAt == nil || !item.DueAt.Equal(dueAt) {
		t.Fatalf("DueAt = %v, want %v", item.DueAt, dueAt)
	}
	if len(item.Controls) != 1 || item.Controls[0].ControlID != "CC6.1" {
		t.Fatalf("Controls = %#v, want SOC 2 CC6.1", item.Controls)
	}
}

func TestControlItemsGroupOpenFindingsByControl(t *testing.T) {
	items := ControlItems([]FindingItem{
		{ID: "critical", Severity: "CRITICAL", Status: "OPEN", EvidenceCount: 2, Controls: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}}},
		{ID: "high", Severity: "HIGH", Status: "OPEN", EvidenceCount: 1, Controls: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}}},
		{ID: "resolved", Severity: "LOW", Status: "RESOLVED", Controls: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.2"}}},
	}, nil)
	if len(items) != 2 {
		t.Fatalf("len(ControlItems) = %d, want 2", len(items))
	}
	control := items[0]
	if control.FrameworkName != "SOC 2" || control.ControlID != "CC6.1" {
		t.Fatalf("first control = %s %s, want SOC 2 CC6.1", control.FrameworkName, control.ControlID)
	}
	if control.Status != "failing" || control.OpenFindings != 2 || control.CriticalFindings != 1 || control.HighFindings != 1 || control.EvidenceItems != 3 {
		t.Fatalf("control posture = %#v", control)
	}
}
