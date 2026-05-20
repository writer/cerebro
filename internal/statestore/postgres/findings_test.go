package postgres

import (
	"context"
	"database/sql"
	"slices"
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

func TestNormalizeFindingObservationWindowDefaultsBothZero(t *testing.T) {
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	first, last := normalizeFindingObservationWindow(time.Time{}, time.Time{}, now)
	if !first.Equal(now) {
		t.Fatalf("first observed at = %v, want %v", first, now)
	}
	if !last.Equal(now) {
		t.Fatalf("last observed at = %v, want %v", last, now)
	}
}

func TestNormalizeFindingObservationWindowFillsMissingBound(t *testing.T) {
	observedAt := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	first, last := normalizeFindingObservationWindow(time.Time{}, observedAt, observedAt.Add(time.Hour))
	if !first.Equal(observedAt) || !last.Equal(observedAt) {
		t.Fatalf("window = (%v, %v), want both %v", first, last, observedAt)
	}
}

func TestListFindingsRejectsMissingTenantID(t *testing.T) {
	store := &Store{}
	if _, err := store.ListFindings(context.Background(), ports.ListFindingsRequest{}); err == nil {
		t.Fatal("ListFindings() error = nil, want non-nil")
	}
}

// ListFindings now requires either runtime_id or rule_id (graph rules query the tenant by
// rule because the projected graph has no per-runtime partition for shared entities like
// okta.user). Sending tenant alone would scan the table.
func TestListFindingsRejectsMissingRuntimeAndRule(t *testing.T) {
	store := &Store{}
	if _, err := store.ListFindings(context.Background(), ports.ListFindingsRequest{TenantID: "writer"}); err == nil {
		t.Fatal("ListFindings() error = nil, want non-nil")
	}
}

func TestListFindingsRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	if _, err := store.ListFindings(context.Background(), ports.ListFindingsRequest{TenantID: "writer", RuntimeID: "writer-okta-audit"}); err == nil {
		t.Fatal("ListFindings() error = nil, want non-nil")
	}
}

// Graph rules call ListFindings with tenant + rule (no runtime) so the contract must accept
// that combination; only an unconfigured Store should fail at this point.
func TestListFindingsAcceptsTenantAndRuleWithoutRuntime(t *testing.T) {
	store := &Store{}
	_, err := store.ListFindings(context.Background(), ports.ListFindingsRequest{
		TenantID: "writer",
		RuleID:   "identity-okta-deprovisioned-active-in-github",
	})
	if err == nil {
		t.Fatal("ListFindings() error = nil, want unconfigured store error")
	}
	if got := err.Error(); strings.Contains(got, "runtime id") || strings.Contains(got, "rule id is required") {
		t.Fatalf("ListFindings() rejected tenant+rule combination: %v", err)
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

func TestLinkFindingTicketRejectsEmptyURL(t *testing.T) {
	store := &Store{}
	if _, err := store.LinkFindingTicket(context.Background(), ports.FindingTicketLink{FindingID: "finding-1"}); err == nil {
		t.Fatal("LinkFindingTicket() error = nil, want non-nil")
	}
}

// runtime_id must be pinned on conflict so the same fingerprint stays addressable on the
// originally-observed runtime instead of flipping. Event-rule fingerprints already include
// runtime_id (so the clause is a no-op for them); graph-rule fingerprints are tenant-scoped
// and the same offender can be emitted by multiple triggering runtimes (okta inventory or
// github audit for the deprovisioned-Okta-active-in-GitHub rule), so without this pin every
// reevaluation would rebind runtime_id and per-runtime list/evidence/report/GRC paths would
// swap the finding in and out under each side.
func TestUpsertFindingStatementPreservesRuntimeIDOnConflict(t *testing.T) {
	if !strings.Contains(upsertFindingStatement, "runtime_id = findings.runtime_id") {
		t.Fatalf("upsertFindingStatement does not preserve runtime_id on conflict; graph-rule findings would flip between triggering runtimes:\n%s", upsertFindingStatement)
	}
	if strings.Contains(upsertFindingStatement, "runtime_id = EXCLUDED.runtime_id") {
		t.Fatalf("upsertFindingStatement still rebinds runtime_id from EXCLUDED on conflict; this would break graph-rule pinning:\n%s", upsertFindingStatement)
	}
}

func TestFindingBackfillRiskUsesRuntimeScorerSignals(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	risk := findingBackfillRisk(&ports.FindingRecord{
		ID:             "finding-1",
		Status:         "open",
		Severity:       "HIGH",
		LastObservedAt: now.Add(-30 * time.Minute),
		Attributes: map[string]string{
			"epss_score":    "0.9",
			"network_scope": "private",
		},
	}, now)
	if !slices.Contains(risk.RiskReasons, "epss_high") {
		t.Fatalf("findingBackfillRisk().RiskReasons = %#v, want epss_high from runtime scorer", risk.RiskReasons)
	}
	if !slices.Contains(risk.RiskReasons, "recent_24h") {
		t.Fatalf("findingBackfillRisk().RiskReasons = %#v, want recent_24h from runtime scorer", risk.RiskReasons)
	}
	if !slices.Contains(risk.RiskReasons, "private_network_context") {
		t.Fatalf("findingBackfillRisk().RiskReasons = %#v, want private_network_context from runtime scorer", risk.RiskReasons)
	}
	if risk.RiskModelVersion != "likelihood-impact-v1" {
		t.Fatalf("findingBackfillRisk().RiskModelVersion = %q, want likelihood-impact-v1", risk.RiskModelVersion)
	}
}

func TestFindingListQueryAcceptsTenantAndRuleWithoutRuntime(t *testing.T) {
	query, args, err := findingListQuery(ports.ListFindingsRequest{
		TenantID: "writer",
		RuleID:   "identity-okta-deprovisioned-active-in-github",
		Status:   "open",
	})
	if err != nil {
		t.Fatalf("findingListQuery() error = %v", err)
	}
	if !strings.Contains(query, "tenant_id = $1") {
		t.Fatalf("findingListQuery() missing tenant clause: %s", query)
	}
	if strings.Contains(query, "runtime_id = ") {
		t.Fatalf("findingListQuery() injected runtime_id clause for tenant+rule scope: %s", query)
	}
	if !strings.Contains(query, "rule_id = $2") {
		t.Fatalf("findingListQuery() did not slot rule_id at $2 when runtime is omitted: %s", query)
	}
	if !strings.Contains(query, "status = $3") {
		t.Fatalf("findingListQuery() did not slot status at $3 when runtime is omitted: %s", query)
	}
	if got := len(args); got != 3 {
		t.Fatalf("len(findingListQuery().args) = %d, want 3", got)
	}
	if got := args[1]; got != "identity-okta-deprovisioned-active-in-github" {
		t.Fatalf("findingListQuery().args[1] = %#v, want rule id", got)
	}
}

func TestFindingListQueryIncludesOptionalFilters(t *testing.T) {
	query, args, err := findingListQuery(ports.ListFindingsRequest{
		TenantID:    "tenant-a",
		RuntimeID:   "runtime-audit",
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
		"tenant_id = $1",
		"runtime_id = $2",
		"id = $3",
		"rule_id = $4",
		"severity = $5",
		"status = $6",
		"policy_id = $7",
		"resource_urns_json @> $8::jsonb",
		"event_ids_json @> $9::jsonb",
		"LIMIT $10",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingListQuery() query missing %q: %s", fragment, query)
		}
	}
	if got := len(args); got != 10 {
		t.Fatalf("len(findingListQuery().args) = %d, want 10", got)
	}
	if got := args[0]; got != "tenant-a" {
		t.Fatalf("findingListQuery().args[0] = %#v, want tenant-a", got)
	}
	if got := args[1]; got != "runtime-audit" {
		t.Fatalf("findingListQuery().args[1] = %#v, want runtime-audit", got)
	}
	if got := args[6]; got != "pol-1" {
		t.Fatalf("findingListQuery().args[6] = %#v, want pol-1", got)
	}
	if got := args[7]; got != `["urn:cerebro:writer:okta_resource:policyrule:pol-1"]` {
		t.Fatalf("findingListQuery().args[7] = %#v, want resource urn array json", got)
	}
	if got := args[8]; got != `["okta-audit-2"]` {
		t.Fatalf("findingListQuery().args[8] = %#v, want event id array json", got)
	}
	if got := args[9]; got != int64(25) {
		t.Fatalf("findingListQuery().args[9] = %#v, want 25", got)
	}
}

func TestFindingListQuerySupportsRuntimeBatchesAndPriorityOrder(t *testing.T) {
	query, args, err := findingListQuery(ports.ListFindingsRequest{
		TenantID:      "writer",
		RuntimeIDs:    []string{"runtime-alpha", "runtime-beta", "runtime-alpha"},
		Status:        "open",
		Limit:         25,
		PriorityOrder: true,
	})
	if err != nil {
		t.Fatalf("findingListQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"tenant_id = $1",
		"runtime_id IN ($2, $3)",
		"status = $4",
		"risk_score DESC",
		"CASE UPPER(severity)",
		"last_observed_at DESC, id",
		"LIMIT $5",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingListQuery() query missing %q: %s", fragment, query)
		}
	}
	if got := len(args); got != 5 {
		t.Fatalf("len(findingListQuery().args) = %d, want 5", got)
	}
	if got := args[1]; got != "runtime-alpha" {
		t.Fatalf("findingListQuery().args[1] = %#v, want first runtime", got)
	}
	if got := args[2]; got != "runtime-beta" {
		t.Fatalf("findingListQuery().args[2] = %#v, want second runtime", got)
	}
	if got := args[4]; got != int64(25) {
		t.Fatalf("findingListQuery().args[4] = %#v, want 25", got)
	}
}

func TestFindingListQueryRiskOrderKeepsSeverityTieBreak(t *testing.T) {
	query, _, err := findingListQuery(ports.ListFindingsRequest{
		TenantID:  "tenant-a",
		RuntimeID: "runtime-audit",
		Order:     ports.FindingOrderRiskScore,
	})
	if err != nil {
		t.Fatalf("findingListQuery() error = %v", err)
	}
	riskIndex := strings.Index(query, "risk_score DESC")
	severityIndex := strings.Index(query, "CASE UPPER(severity)")
	observedIndex := strings.Index(query, "last_observed_at DESC")
	if riskIndex == -1 || severityIndex == -1 || observedIndex == -1 {
		t.Fatalf("findingListQuery() query missing risk/severity/observed ordering: %s", query)
	}
	if riskIndex >= severityIndex || severityIndex >= observedIndex {
		t.Fatalf("findingListQuery() ordering = %s, want risk then severity tie-break then recency", query)
	}
}

func TestFindingRowRecordDecodesCheckAndControlMetadata(t *testing.T) {
	record, err := (findingRow{
		ID:          "finding-1",
		Fingerprint: "fingerprint-1",
		TenantID:    "tenant-a",
		RuntimeID:   "runtime-audit",
		RuleID:      "identity-okta-policy-rule-lifecycle-tampering",
		Title:       "Okta Policy Rule Lifecycle Tampering",
		Severity:    "HIGH",
		Status:      "open",
		Summary:     "admin@example.invalid performed policy.rule.update on pol-1",
		findingRiskRow: findingRiskRow{
			RiskScore:        82,
			LikelihoodScore:  78,
			ImpactScore:      86,
			ConfidenceScore:  93,
			LikelihoodLevel:  "high",
			ImpactLevel:      "critical",
			RiskReasonsJSON:  `["external_exposure","privileged_actor"]`,
			RiskModelVersion: "likelihood-impact-v1",
		},
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
			NotesJSON:   `[{"id":"note-1","body":"Escalate to identity engineering.","created_at":"2026-05-01T11:00:00Z"}]`,
			TicketsJSON: `[{"url":"https://jira.writer.com/browse/ENG-123","name":"ENG-123","external_id":"ENG-123","linked_at":"2026-05-01T11:30:00Z"}]`,
			DueAt:       sql.NullTime{Time: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC), Valid: true},
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
	if got := record.RiskScore; got != 82 {
		t.Fatalf("findingRow.record().RiskScore = %d, want 82", got)
	}
	if got := record.LikelihoodScore; got != 78 {
		t.Fatalf("findingRow.record().LikelihoodScore = %d, want 78", got)
	}
	if got := record.ImpactScore; got != 86 {
		t.Fatalf("findingRow.record().ImpactScore = %d, want 86", got)
	}
	if got := record.ConfidenceScore; got != 93 {
		t.Fatalf("findingRow.record().ConfidenceScore = %d, want 93", got)
	}
	if got := record.LikelihoodLevel; got != "high" {
		t.Fatalf("findingRow.record().LikelihoodLevel = %q, want high", got)
	}
	if got := record.ImpactLevel; got != "critical" {
		t.Fatalf("findingRow.record().ImpactLevel = %q, want critical", got)
	}
	if got := record.RiskModelVersion; got != "likelihood-impact-v1" {
		t.Fatalf("findingRow.record().RiskModelVersion = %q, want likelihood-impact-v1", got)
	}
	if !slices.Contains(record.RiskReasons, "external_exposure") || !slices.Contains(record.RiskReasons, "privileged_actor") {
		t.Fatalf("findingRow.record().RiskReasons = %#v, want typed risk reasons", record.RiskReasons)
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
	if got := len(record.Tickets); got != 1 {
		t.Fatalf("len(findingRow.record().Tickets) = %d, want 1", got)
	}
	if got := record.Tickets[0].URL; got != "https://jira.writer.com/browse/ENG-123" {
		t.Fatalf("findingRow.record().Tickets[0].URL = %q, want ticket url", got)
	}
}
