package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	findingrisk "github.com/writer/cerebro/internal/findings"
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

func TestListGRCFindingsRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	if _, err := store.ListGRCFindings(context.Background(), ports.ListFindingsRequest{TenantID: "tenant", RuntimeID: "runtime-alpha"}); err == nil {
		t.Fatal("ListGRCFindings() error = nil, want non-nil")
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

func TestLinkFindingExternalRefStatementRefreshesMatchingObject(t *testing.T) {
	if !strings.Contains(linkFindingExternalRefStatement, "WHEN ref @> ($3::jsonb -> 0) THEN ($2::jsonb -> 0)") {
		t.Fatalf("linkFindingExternalRefStatement must refresh matching JSON object instead of appending duplicates:\n%s", linkFindingExternalRefStatement)
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
	if risk.RiskModelVersion != "likelihood-impact-v2" {
		t.Fatalf("findingBackfillRisk().RiskModelVersion = %q, want likelihood-impact-v2", risk.RiskModelVersion)
	}
	if len(risk.RiskFactors) == 0 {
		t.Fatal("findingBackfillRisk().RiskFactors is empty, want evidence-backed factors")
	}
}

func TestFindingRiskAttributesForUpdateIncludesEffectiveSeverity(t *testing.T) {
	attributes := findingRiskAttributesForUpdate(ports.FindingRisk{
		RiskScore: 72,
		RiskFactors: []ports.FindingRiskFactor{{
			FactorID:             "external_exposure",
			Category:             "likelihood",
			Weight:               35,
			SeverityContribution: "high",
			EvidenceRefs:         []string{"attribute:internet_exposed"},
			SuppressionScope:     "factor:external_exposure",
		}},
	}, "low")
	if got := attributes["effective_severity"]; got != "HIGH" {
		t.Fatalf("effective_severity = %q, want HIGH", got)
	}
	if got := attributes["source_severity"]; got != "LOW" {
		t.Fatalf("source_severity = %q, want LOW", got)
	}
	if got := attributes[findingrisk.FindingRiskFactorsAttribute]; !strings.Contains(got, `"factor_id":"external_exposure"`) {
		t.Fatalf("risk factors attribute = %q, want external_exposure JSON", got)
	}
}

func TestFindingListQueryAcceptsTenantAndRuleWithoutRuntimeUnbounded(t *testing.T) {
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
	if strings.Contains(query, "LIMIT") {
		t.Fatalf("findingListQuery() applied LIMIT for unbounded internal request: %s", query)
	}
	if got := len(args); got != 3 {
		t.Fatalf("len(findingListQuery().args) = %d, want 3", got)
	}
	if got := args[1]; got != "identity-okta-deprovisioned-active-in-github" {
		t.Fatalf("findingListQuery().args[1] = %#v, want rule id", got)
	}
}

func TestFindingListQueryClampsExplicitLimit(t *testing.T) {
	query, args, err := findingListQuery(ports.ListFindingsRequest{
		TenantID: "writer",
		RuleID:   "identity-okta-deprovisioned-active-in-github",
		Status:   "open",
		Limit:    maxFindingListLimit + 1,
	})
	if err != nil {
		t.Fatalf("findingListQuery() error = %v", err)
	}
	if !strings.Contains(query, "LIMIT $4") {
		t.Fatalf("findingListQuery() did not apply LIMIT at $4: %s", query)
	}
	if got := len(args); got != 4 {
		t.Fatalf("len(findingListQuery().args) = %d, want 4", got)
	}
	if got := args[3]; got != int64(maxFindingListLimit) {
		t.Fatalf("findingListQuery().args[3] = %#v, want max limit", got)
	}
}

func TestFindingGRCListQueryAvoidsFullPayload(t *testing.T) {
	query, args, err := findingGRCListQuery(ports.ListFindingsRequest{
		TenantID:   "tenant",
		RuntimeIDs: []string{"runtime-alpha", "runtime-beta"},
		Status:     "open",
		Limit:      25,
		Order:      ports.FindingOrderRiskScore,
	})
	if err != nil {
		t.Fatalf("findingGRCListQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"SELECT id, tenant_id, runtime_id, rule_id, title, UPPER(COALESCE(NULLIF(attributes_json->>'effective_severity', ''), severity)) AS severity",
		"risk_reasons_json::text",
		"resource_urns_json::text",
		"control_refs_json::text",
		"runtime_id IN ($2, $3)",
		"status = $4",
		"ORDER BY risk_score DESC",
		"LIMIT $5",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingGRCListQuery() query missing %q: %s", fragment, query)
		}
	}
	for _, forbidden := range []string{
		"fingerprint",
		"event_ids_json::text",
		"observed_policy_ids_json::text",
		"notes_json",
		"tickets_json",
		"attributes_json::text",
		"tombstoned_by",
		"tombstoned_reason",
		"status_reason",
		"check_name",
	} {
		if strings.Contains(query, forbidden) {
			t.Fatalf("findingGRCListQuery() selected unused payload %q: %s", forbidden, query)
		}
	}
	if got := len(args); got != 5 {
		t.Fatalf("len(findingGRCListQuery().args) = %d, want 5", got)
	}
}

func TestFindingFilterClausesSupportTrendDrilldownFilters(t *testing.T) {
	openedAfter := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	openedBefore := openedAfter.AddDate(0, 0, 7)
	closedAfter := time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC)
	closedBefore := closedAfter.AddDate(0, 0, 7)
	clauses, args, err := findingFilterClauses(ports.ListFindingsRequest{
		TenantID:            "tenant",
		RuntimeIDs:          []string{"runtime-alpha"},
		Framework:           "SOC 2",
		FirstObservedFrom:   openedAfter,
		FirstObservedBefore: openedBefore,
		StatusUpdatedFrom:   closedAfter,
		StatusUpdatedBefore: closedBefore,
		MinAgeDays:          8,
		MaxAgeDays:          30,
		SLAStatus:           "overdue",
	})
	if err != nil {
		t.Fatalf("findingFilterClauses() error = %v", err)
	}
	query := strings.Join(clauses, " AND ")
	for _, fragment := range []string{
		"jsonb_array_elements",
		"first_observed_at >= $4",
		"first_observed_at < $5",
		"status_updated_at >= $6",
		"status_updated_at < $7",
		"first_observed_at <= NOW() - ($8::int * INTERVAL '1 day')",
		"first_observed_at > NOW() - (($9::int + 1) * INTERVAL '1 day')",
		"due_at < NOW()",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingFilterClauses() missing %q in %s", fragment, query)
		}
	}
	if got := len(args); got != 9 {
		t.Fatalf("len(args) = %d, want 9", got)
	}
}

func TestFindingCandidateListQueryRequiresTenantAndScope(t *testing.T) {
	if _, _, err := findingCandidateListQuery(ports.ListFindingCandidatesRequest{RuntimeID: "writer-okta-audit"}); err == nil {
		t.Fatal("findingCandidateListQuery() error = nil, want tenant error")
	}
	if _, _, err := findingCandidateListQuery(ports.ListFindingCandidatesRequest{TenantID: "writer"}); err == nil {
		t.Fatal("findingCandidateListQuery() error = nil, want scope error")
	}
}

func TestFindingCandidateListQueryFiltersRuntimeRuleStatusAndFingerprint(t *testing.T) {
	query, args, err := findingCandidateListQuery(ports.ListFindingCandidatesRequest{
		TenantID:    "writer",
		RuntimeID:   "writer-okta-audit",
		RuleID:      "rule-a",
		Status:      "candidate",
		Fingerprint: "fingerprint-1",
		Limit:       5,
	})
	if err != nil {
		t.Fatalf("findingCandidateListQuery() error = %v", err)
	}
	for _, want := range []string{"tenant_id = $1", "runtime_id = $2", "rule_id = $3", "status = $4", "fingerprint = $5", "LIMIT $6"} {
		if !strings.Contains(query, want) {
			t.Fatalf("findingCandidateListQuery() missing %q in query: %s", want, query)
		}
	}
	if got := len(args); got != 6 {
		t.Fatalf("len(args) = %d, want 6", got)
	}
}

func TestValidateFindingCandidateRequiresSnapshotAndLastRun(t *testing.T) {
	err := validateFindingCandidate(&ports.FindingCandidateRecord{
		ID:          "candidate-1",
		TenantID:    "writer",
		RuntimeID:   "writer-okta-audit",
		RuleID:      "rule-a",
		Fingerprint: "fingerprint-1",
	})
	if err == nil {
		t.Fatal("validateFindingCandidate() error = nil, want missing last run/finding error")
	}
	valid := &ports.FindingCandidateRecord{
		ID:          "candidate-1",
		TenantID:    "writer",
		RuntimeID:   "writer-okta-audit",
		RuleID:      "rule-a",
		Fingerprint: "fingerprint-1",
		LastRunID:   "candidate-run-1",
		Finding:     newUpsertFinding("finding-1", "fingerprint-1", "open", time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)),
	}
	if err := validateFindingCandidate(valid); err != nil {
		t.Fatalf("validateFindingCandidate() error = %v", err)
	}
}

func TestMarkFindingCandidateRejectedValidatesReviewMetadata(t *testing.T) {
	store := &Store{}
	_, err := store.MarkFindingCandidateRejected(context.Background(), ports.FindingCandidateRejection{
		CandidateID: "candidate-1",
		DecisionID:  "decision-1",
		RejectedBy:  "analyst@example.com",
	})
	if err == nil {
		t.Fatal("MarkFindingCandidateRejected() error = nil, want missing rationale error")
	}
	_, err = store.MarkFindingCandidateRejected(context.Background(), ports.FindingCandidateRejection{
		CandidateID: "candidate-1",
		DecisionID:  "decision-1",
		RejectedBy:  "analyst@example.com",
		Rationale:   "Expected fixture candidate.",
	})
	if err == nil {
		t.Fatal("MarkFindingCandidateRejected() error = nil, want unconfigured postgres error")
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
		"attributes_json->>'effective_severity'",
		"= $5",
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
		"CASE UPPER(COALESCE(NULLIF(attributes_json->>'effective_severity'",
		"last_observed_at DESC, id",
		"LIMIT $5",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingListQuery() query missing %q: %s", fragment, query)
		}
	}
	if strings.Contains(query, "risk_score DESC") {
		t.Fatalf("findingListQuery() priority order includes risk score ordering: %s", query)
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
	severityIndex := strings.Index(query, "CASE UPPER(COALESCE(NULLIF(attributes_json->>'effective_severity'")
	observedIndex := strings.Index(query, "last_observed_at DESC")
	if riskIndex == -1 || severityIndex == -1 || observedIndex == -1 {
		t.Fatalf("findingListQuery() query missing risk/severity/observed ordering: %s", query)
	}
	if riskIndex >= severityIndex || severityIndex >= observedIndex {
		t.Fatalf("findingListQuery() ordering = %s, want risk then severity tie-break then recency", query)
	}
}

func TestEndpointVulnerabilityFindingQueryIncludesIdentityFilters(t *testing.T) {
	query, args := endpointVulnerabilityFindingQuery(ports.EndpointVulnerabilityFindingQuery{
		TenantID:     "writer",
		DeviceID:     "device-1",
		SerialNumber: "serial-1",
		AgentID:      "agent-1",
		Limit:        25,
	})
	for _, fragment := range []string{
		"tenant_id = $1",
		"LOWER(status) = 'open'",
		"COALESCE(LOWER(attributes_json->>'source_freshness'), '') <> 'stale'",
		"COALESCE(LOWER(attributes_json->>'freshness'), '') <> 'stale'",
		"COALESCE(LOWER(attributes_json->>'stale'), '') NOT IN ('1', 't', 'true', 'y', 'yes', 'known', 'listed')",
		"COALESCE(LOWER(attributes_json->>'source_stale'), '') NOT IN ('1', 't', 'true', 'y', 'yes', 'known', 'listed')",
		"NULLIF(BTRIM(attributes_json->>'vulnerability_id'), '') IS NOT NULL",
		"UPPER(BTRIM(attributes_json->>'identifier')) LIKE 'CVE-%'",
		"UPPER(BTRIM(attributes_json->>'identifier')) LIKE 'GHSA-%'",
		"attributes_json->>'device_id' = $2",
		"attributes_json->>'endpoint_id' = $3",
		"attributes_json->>'asset_id' = $4",
		"attributes_json->>'serial_number' = $5",
		"attributes_json->>'agent_id' = $6",
		"attributes_json->>'agent_uuid' = $7",
		"LIMIT $8",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("endpointVulnerabilityFindingQuery() query missing %q: %s", fragment, query)
		}
	}
	if got := len(args); got != 8 {
		t.Fatalf("len(endpointVulnerabilityFindingQuery().args) = %d, want 8", got)
	}
	wantIdentityScope := "((attributes_json->>'device_id' = $2 OR attributes_json->>'endpoint_id' = $3 OR attributes_json->>'asset_id' = $4) OR (attributes_json->>'serial_number' = $5) OR (attributes_json->>'agent_id' = $6 OR attributes_json->>'agent_uuid' = $7))"
	if !strings.Contains(query, wantIdentityScope) {
		t.Fatalf("endpointVulnerabilityFindingQuery() identity scope = %s, want supplied identifiers to be alternatives", query)
	}
	if got := args[0]; got != "writer" {
		t.Fatalf("endpointVulnerabilityFindingQuery().args[0] = %#v, want writer", got)
	}
	if got := args[7]; got != uint32(25) {
		t.Fatalf("endpointVulnerabilityFindingQuery().args[7] = %#v, want 25", got)
	}
}

func TestEndpointVulnerabilityFindingQueryOmitsLimitWhenUnset(t *testing.T) {
	query, args := endpointVulnerabilityFindingQuery(ports.EndpointVulnerabilityFindingQuery{
		TenantID: "writer",
		DeviceID: "device-1",
	})
	if strings.Contains(query, "LIMIT") {
		t.Fatalf("endpointVulnerabilityFindingQuery() query = %s, want no raw row cap without caller limit", query)
	}
	if got := len(args); got != 4 {
		t.Fatalf("len(endpointVulnerabilityFindingQuery().args) = %d, want tenant plus device aliases", got)
	}
}

func TestEndpointVulnerabilityFindingQueryIncludeStaleAndLimitClamp(t *testing.T) {
	query, args := endpointVulnerabilityFindingQuery(ports.EndpointVulnerabilityFindingQuery{
		TenantID:     "writer",
		SerialNumber: "serial-1",
		IncludeStale: true,
		Limit:        1000,
	})
	if !strings.Contains(query, "LOWER(status) NOT IN ('resolved', 'suppressed')") {
		t.Fatalf("endpointVulnerabilityFindingQuery() missing include_stale status clause: %s", query)
	}
	if got := args[len(args)-1]; got != uint32(500) {
		t.Fatalf("endpointVulnerabilityFindingQuery() limit arg = %#v, want 500", got)
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
			RiskModelVersion: "likelihood-impact-v2",
		},
		ResourceURNsJSON:      `["urn:cerebro:writer:okta_resource:policyrule:pol-1"]`,
		EventIDsJSON:          `["okta-audit-2"]`,
		ObservedPolicyIDsJSON: `["pol-1"]`,
		ControlRefsJSON:       `[{"framework_name":"SOC 2","control_id":"CC6.2"},{"framework_name":"ISO 27001:2022","control_id":"A.8.9"}]`,
		PolicyID:              "pol-1",
		PolicyName:            "pol-1",
		CheckID:               "identity-okta-policy-rule-lifecycle-tampering-30d",
		CheckName:             "Okta Policy Rule Lifecycle Tampering (30 days)",
		AttributesJSON:        `{"effective_severity":"MEDIUM","source_severity":"HIGH","primary_resource_urn":"urn:cerebro:writer:okta_resource:policyrule:pol-1"}`,
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
	if got := record.Severity; got != "MEDIUM" {
		t.Fatalf("findingRow.record().Severity = %q, want effective severity MEDIUM", got)
	}
	if got := record.RiskModelVersion; got != "likelihood-impact-v2" {
		t.Fatalf("findingRow.record().RiskModelVersion = %q, want likelihood-impact-v2", got)
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

// upsertStatementContainsBeltAndSuspenders is a static check on the prepared
// statement source that the reopen CASE includes the explicit tombstoned clamp.
func TestUpsertFindingStatementContainsTombstoneClamp(t *testing.T) {
	if !strings.Contains(upsertFindingStatement, "AND NOT findings.tombstoned") {
		t.Fatalf("upsertFindingStatement missing 'AND NOT findings.tombstoned' belt-and-suspenders clamp:\n%s", upsertFindingStatement)
	}
	if !strings.Contains(upsertFindingStatement, "WHERE findings.tombstoned = FALSE") {
		t.Fatalf("upsertFindingStatement must skip ON CONFLICT updates once the targeted row is tombstoned so UpsertFinding can retry with a fresh generation:\n%s", upsertFindingStatement)
	}
}

// The reopen CASE must restrict the open-emit reopen path to resolved rows only.
// Suppressed rows are a manual decision and MUST be preserved across emits.
func TestUpsertFindingStatementPreservesSuppressedOnOpenEmit(t *testing.T) {
	if strings.Contains(upsertFindingStatement, "findings.status IN ('resolved', 'suppressed') AND EXCLUDED.status = 'open'") {
		t.Fatalf("upsertFindingStatement still includes 'suppressed' in the reopen-on-open-emit set; suppressed rows must be preserved:\n%s", upsertFindingStatement)
	}
	if !strings.Contains(upsertFindingStatement, "WHEN findings.status = 'suppressed' THEN findings.status") {
		t.Fatalf("upsertFindingStatement missing explicit suppressed-preservation branch in the status CASE:\n%s", upsertFindingStatement)
	}
	if !strings.Contains(upsertFindingStatement, "WHEN findings.status = 'suppressed' THEN findings.status_reason") {
		t.Fatalf("upsertFindingStatement missing suppressed-preservation branch in the status_reason CASE; suppression reason would be overwritten on emit:\n%s", upsertFindingStatement)
	}
	if !strings.Contains(upsertFindingStatement, "WHEN findings.status = 'suppressed' THEN findings.status_updated_at") {
		t.Fatalf("upsertFindingStatement missing suppressed-preservation branch in the status_updated_at CASE; status_updated_at would be advanced on emit:\n%s", upsertFindingStatement)
	}
}

// Resolved rows only reopen on a fresh open emit when they were TTL-resolved
// (status_reason starts with ttl_expired:) or the rule itself is ttl_evidence.
// Manual resolutions are analyst triage and must remain sticky like suppressed rows.
func TestUpsertFindingStatementLimitsResolvedReopenToTTL(t *testing.T) {
	if !strings.Contains(upsertFindingStatement, "ttl_expired:%") {
		t.Fatalf("upsertFindingStatement missing ttl_expired prefix check in resolved reopen branch:\n%s", upsertFindingStatement)
	}
	if !strings.Contains(upsertFindingStatement, "::boolean") {
		t.Fatalf("upsertFindingStatement missing ttl_evidence lifecycle parameter in resolved reopen branch:\n%s", upsertFindingStatement)
	}
	if !strings.Contains(upsertFindingStatement, "WHEN findings.status = 'resolved' AND EXCLUDED.status = 'open' THEN findings.status") {
		t.Fatalf("upsertFindingStatement missing manual-resolved status preservation branch:\n%s", upsertFindingStatement)
	}
	if !strings.Contains(upsertFindingStatement, "WHEN findings.status = 'resolved' AND EXCLUDED.status = 'open' AND NOT (BTRIM(findings.status_reason) LIKE 'ttl_expired:%'") ||
		!strings.Contains(upsertFindingStatement, "THEN findings.status_reason") {
		t.Fatalf("upsertFindingStatement missing manual-resolved status_reason preservation branch:\n%s", upsertFindingStatement)
	}
	if !strings.Contains(upsertFindingStatement, "THEN findings.status_updated_at") {
		t.Fatalf("upsertFindingStatement missing manual-resolved status_updated_at preservation branch:\n%s", upsertFindingStatement)
	}
}

//nolint:unparam // Helper keeps status explicit for upsert finding fixtures.
func newUpsertFinding(id, fingerprint, status string, observed time.Time) *ports.FindingRecord {
	return &ports.FindingRecord{
		ID:              id,
		Fingerprint:     fingerprint,
		TenantID:        "writer",
		RuntimeID:       "runtime-test",
		RuleID:          "rule-test",
		Title:           "Test finding",
		Severity:        "HIGH",
		Status:          status,
		Summary:         "summary",
		FirstObservedAt: observed,
		LastObservedAt:  observed,
	}
}

func TestLinkFindingExternalRef_RefreshesMatchingReference(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)

	now := time.Now().UTC().Truncate(time.Microsecond)
	baseID := fmt.Sprintf("finding-external-ref-%d", now.UnixNano())
	fp := fmt.Sprintf("fp-external-ref-%d", now.UnixNano())
	if _, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now)); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	first, err := store.LinkFindingExternalRef(ctx, ports.FindingExternalRefLink{
		FindingID: baseID,
		ExternalRef: ports.FindingExternalRef{
			System:         "panopticon",
			Kind:           "alert",
			ExternalID:     "alert-123",
			URL:            "https://panopticon.example/alerts/123",
			ExternalStatus: "open",
			LifecycleOwner: "external_owned",
			ObservedAt:     now,
		},
	})
	if err != nil {
		t.Fatalf("first LinkFindingExternalRef: %v", err)
	}
	if got := len(first.ExternalRefs); got != 1 {
		t.Fatalf("external refs after first link = %d, want 1", got)
	}

	second, err := store.LinkFindingExternalRef(ctx, ports.FindingExternalRefLink{
		FindingID: baseID,
		ExternalRef: ports.FindingExternalRef{
			System:               "panopticon",
			Kind:                 "alert",
			ExternalID:           "alert-123",
			URL:                  "https://panopticon.example/alerts/123",
			ExternalStatus:       "closed",
			ExternalStatusReason: "triaged false positive",
			LifecycleOwner:       "external_owned",
			ObservedAt:           now.Add(time.Minute),
		},
	})
	if err != nil {
		t.Fatalf("second LinkFindingExternalRef: %v", err)
	}
	if got := len(second.ExternalRefs); got != 1 {
		t.Fatalf("external refs after refresh = %d, want 1", got)
	}
	ref := second.ExternalRefs[0]
	if got := ref.ExternalStatus; got != "closed" {
		t.Fatalf("ExternalStatus = %q, want closed", got)
	}
	if got := ref.ExternalStatusReason; got != "triaged false positive" {
		t.Fatalf("ExternalStatusReason = %q, want triaged false positive", got)
	}

	third, err := store.LinkFindingExternalRef(ctx, ports.FindingExternalRefLink{
		FindingID: baseID,
		ExternalRef: ports.FindingExternalRef{
			System:         "panopticon",
			Kind:           "alert",
			ExternalID:     "alert-456",
			ExternalStatus: "open",
			LifecycleOwner: "external_owned",
			ObservedAt:     now.Add(2 * time.Minute),
		},
	})
	if err != nil {
		t.Fatalf("third LinkFindingExternalRef: %v", err)
	}
	if got := len(third.ExternalRefs); got != 2 {
		t.Fatalf("external refs after distinct link = %d, want 2", got)
	}
}

func TestFindingRuleAllowsTTLReopenUsesLifecycleMetadata(t *testing.T) {
	if !findingRuleAllowsTTLReopen("runtime-active-threat-evidence") {
		t.Fatal("runtime-active-threat-evidence should be recognized as ttl_evidence for reopen-on-emit")
	}
	if findingRuleAllowsTTLReopen("rule-test") {
		t.Fatal("non-ttl_evidence rule-test unexpectedly allowed resolved reopen-on-emit")
	}
}

func tombstoneRowSnapshot(t *testing.T, ctx context.Context, store *Store, id string) map[string]any {
	t.Helper()
	row := store.db.QueryRowContext(ctx, `
        SELECT status, tombstoned, tombstoned_at, tombstoned_by, tombstoned_reason,
               tombstoned_run_id, prior_status, tombstone_generation
          FROM findings WHERE id = $1`, id)
	var (
		status, tombstonedBy, tombstonedReason, tombstonedRunID, priorStatus string
		tombstoned                                                           bool
		tombstonedAt                                                         sql.NullTime
		generation                                                           int
	)
	if err := row.Scan(&status, &tombstoned, &tombstonedAt, &tombstonedBy, &tombstonedReason, &tombstonedRunID, &priorStatus, &generation); err != nil {
		t.Fatalf("snapshot tombstone row %q: %v", id, err)
	}
	snap := map[string]any{
		"status":               status,
		"tombstoned":           tombstoned,
		"tombstoned_by":        tombstonedBy,
		"tombstoned_reason":    tombstonedReason,
		"tombstoned_run_id":    tombstonedRunID,
		"prior_status":         priorStatus,
		"tombstone_generation": generation,
	}
	if tombstonedAt.Valid {
		snap["tombstoned_at"] = tombstonedAt.Time.UTC().Format(time.RFC3339Nano)
	} else {
		snap["tombstoned_at"] = nil
	}
	return snap
}

func TestUpsertFinding_PreservesManualResolvedOnOpenEmit(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	now := time.Now().UTC().Truncate(time.Microsecond)
	fp := fmt.Sprintf("fp-manual-resolved-%d", now.UnixNano())
	baseID := fmt.Sprintf("finding-manual-resolved-%d", now.UnixNano())

	stored, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now.Add(-time.Hour)))
	if err != nil {
		t.Fatalf("initial upsert: %v", err)
	}
	if stored.Status != "open" {
		t.Fatalf("initial status = %q, want open", stored.Status)
	}
	if stored.ID != baseID {
		t.Fatalf("initial id = %q, want %q", stored.ID, baseID)
	}

	resolvedAt := now.Add(-30 * time.Minute)
	if _, err := store.db.ExecContext(ctx,
		`UPDATE findings SET status = 'resolved', status_reason = 'remediated', status_updated_at = $2 WHERE id = $1`,
		baseID, resolvedAt); err != nil {
		t.Fatalf("manually resolve: %v", err)
	}

	afterEmit, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now))
	if err != nil {
		t.Fatalf("manual-resolved emit upsert: %v", err)
	}
	if afterEmit.Status != "resolved" {
		t.Fatalf("post-emit status = %q, want resolved (manual resolution must stay sticky)", afterEmit.Status)
	}
	if afterEmit.StatusReason != "remediated" {
		t.Fatalf("post-emit status_reason = %q, want remediated", afterEmit.StatusReason)
	}
	if !afterEmit.StatusUpdatedAt.Equal(resolvedAt) {
		t.Fatalf("post-emit status_updated_at = %v, want %v", afterEmit.StatusUpdatedAt, resolvedAt)
	}
	if afterEmit.ID != baseID {
		t.Fatalf("post-emit id = %q, want %q", afterEmit.ID, baseID)
	}

	var rowCount int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE fingerprint = $1`, fp).Scan(&rowCount); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rowCount != 1 {
		t.Fatalf("rows for fingerprint = %d, want exactly 1", rowCount)
	}
}

func TestUpsertFinding_ReopensTTLResolvedOnOpenEmit(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	now := time.Now().UTC().Truncate(time.Microsecond)
	fp := fmt.Sprintf("fp-ttl-resolved-%d", now.UnixNano())
	baseID := fmt.Sprintf("finding-ttl-resolved-%d", now.UnixNano())

	if _, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now.Add(-time.Hour))); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	if _, err := store.db.ExecContext(ctx,
		`UPDATE findings SET status = 'resolved', status_reason = 'ttl_expired:24h', status_updated_at = $2 WHERE id = $1`,
		baseID, now.Add(-30*time.Minute)); err != nil {
		t.Fatalf("ttl resolve: %v", err)
	}

	reopened, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now))
	if err != nil {
		t.Fatalf("ttl-resolved reopen upsert: %v", err)
	}
	if reopened.Status != "open" {
		t.Fatalf("post-emit status = %q, want open", reopened.Status)
	}
	if reopened.StatusReason != "" {
		t.Fatalf("post-emit status_reason = %q, want empty after reopen", reopened.StatusReason)
	}
	if reopened.ID != baseID {
		t.Fatalf("post-emit id = %q, want %q (id must be unchanged on TTL reopen)", reopened.ID, baseID)
	}

	var rowCount int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE fingerprint = $1`, fp).Scan(&rowCount); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rowCount != 1 {
		t.Fatalf("rows for fingerprint = %d, want exactly 1", rowCount)
	}
}

func TestUpsertFinding_ReopensTTLEvidenceRuleResolvedOnOpenEmit(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	now := time.Now().UTC().Truncate(time.Microsecond)
	fp := fmt.Sprintf("fp-ttl-rule-%d", now.UnixNano())
	baseID := fmt.Sprintf("finding-ttl-rule-%d", now.UnixNano())
	finding := newUpsertFinding(baseID, fp, "open", now.Add(-time.Hour))
	finding.RuleID = "runtime-active-threat-evidence"

	if _, err := store.UpsertFinding(ctx, finding); err != nil {
		t.Fatalf("seed ttl_evidence finding: %v", err)
	}

	if _, err := store.db.ExecContext(ctx,
		`UPDATE findings SET status = 'resolved', status_reason = 'manual-close-on-ttl-rule', status_updated_at = $2 WHERE id = $1`,
		baseID, now.Add(-30*time.Minute)); err != nil {
		t.Fatalf("resolve ttl_evidence finding: %v", err)
	}

	reemit := newUpsertFinding(baseID, fp, "open", now)
	reemit.RuleID = "runtime-active-threat-evidence"
	reopened, err := store.UpsertFinding(ctx, reemit)
	if err != nil {
		t.Fatalf("ttl_evidence rule reopen upsert: %v", err)
	}
	if reopened.Status != "open" {
		t.Fatalf("post-emit status = %q, want open for ttl_evidence rule", reopened.Status)
	}
	if reopened.ID != baseID {
		t.Fatalf("post-emit id = %q, want %q", reopened.ID, baseID)
	}
}

func TestUpsertFinding_PreservesSuppressedOnOpenEmit(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	now := time.Now().UTC().Truncate(time.Microsecond)
	fp := fmt.Sprintf("fp-suppress-%d", now.UnixNano())
	baseID := fmt.Sprintf("finding-suppress-%d", now.UnixNano())

	if _, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now.Add(-time.Hour))); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	suppressedAt := now.Add(-30 * time.Minute)
	if _, err := store.db.ExecContext(ctx,
		`UPDATE findings
            SET status = 'suppressed',
                status_reason = 'analyst suppressed: false positive',
                status_updated_at = $2,
                assignee = 'alice@writer.com'
          WHERE id = $1`,
		baseID, suppressedAt); err != nil {
		t.Fatalf("manually suppress: %v", err)
	}

	var (
		beforeStatus, beforeReason, beforeAssignee string
		beforeUpdatedAt                            sql.NullTime
		beforeTombstoned                           bool
	)
	if err := store.db.QueryRowContext(ctx,
		`SELECT status, status_reason, status_updated_at, assignee, tombstoned FROM findings WHERE id = $1`, baseID,
	).Scan(&beforeStatus, &beforeReason, &beforeUpdatedAt, &beforeAssignee, &beforeTombstoned); err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	if beforeStatus != "suppressed" {
		t.Fatalf("pre-emit status = %q, want suppressed", beforeStatus)
	}

	emitted, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now))
	if err != nil {
		t.Fatalf("open emit upsert: %v", err)
	}
	if emitted.Status != "suppressed" {
		t.Fatalf("post-emit status = %q, want suppressed (suppressed is a manual decision and must be preserved)", emitted.Status)
	}
	if emitted.ID != baseID {
		t.Fatalf("post-emit id = %q, want %q", emitted.ID, baseID)
	}

	var (
		afterStatus, afterReason, afterAssignee string
		afterUpdatedAt                          sql.NullTime
		afterTombstoned                         bool
	)
	if err := store.db.QueryRowContext(ctx,
		`SELECT status, status_reason, status_updated_at, assignee, tombstoned FROM findings WHERE id = $1`, baseID,
	).Scan(&afterStatus, &afterReason, &afterUpdatedAt, &afterAssignee, &afterTombstoned); err != nil {
		t.Fatalf("snapshot after: %v", err)
	}

	if afterStatus != beforeStatus {
		t.Fatalf("status changed: before=%q after=%q", beforeStatus, afterStatus)
	}
	if afterReason != beforeReason {
		t.Fatalf("status_reason changed: before=%q after=%q (suppression reason must be preserved)", beforeReason, afterReason)
	}
	if afterAssignee != beforeAssignee {
		t.Fatalf("assignee changed: before=%q after=%q", beforeAssignee, afterAssignee)
	}
	if afterTombstoned != beforeTombstoned {
		t.Fatalf("tombstoned changed: before=%v after=%v", beforeTombstoned, afterTombstoned)
	}
	if !afterUpdatedAt.Valid || !beforeUpdatedAt.Valid {
		t.Fatalf("status_updated_at must be set both before and after: before=%v after=%v", beforeUpdatedAt, afterUpdatedAt)
	}
	if !afterUpdatedAt.Time.Equal(beforeUpdatedAt.Time) {
		t.Fatalf("status_updated_at advanced on emit: before=%v after=%v (must be preserved for suppressed rows)", beforeUpdatedAt.Time, afterUpdatedAt.Time)
	}

	var rowCount int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE fingerprint = $1`, fp).Scan(&rowCount); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rowCount != 1 {
		t.Fatalf("rows for fingerprint = %d, want exactly 1 (no fresh row should be minted for a suppressed active row)", rowCount)
	}
}

func TestUpsertFinding_DoesNotReopenTombstoned(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	now := time.Now().UTC().Truncate(time.Microsecond)
	fp := fmt.Sprintf("fp-tombstone-%d", now.UnixNano())
	baseID := fmt.Sprintf("finding-tombstone-%d", now.UnixNano())

	if _, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now.Add(-2*time.Hour))); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
        UPDATE findings
           SET status = 'resolved',
               tombstoned = TRUE,
               tombstoned_at = $2,
               tombstoned_by = 'tester',
               tombstoned_reason = 'closeout',
               tombstoned_run_id = 'run-1',
               prior_status = 'open',
               tombstone_generation = 0
         WHERE id = $1`, baseID, now.Add(-time.Hour)); err != nil {
		t.Fatalf("tombstone seed: %v", err)
	}

	before := tombstoneRowSnapshot(t, ctx, store, baseID)

	if _, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now)); err != nil {
		t.Fatalf("emit upsert after tombstone: %v", err)
	}

	after := tombstoneRowSnapshot(t, ctx, store, baseID)
	for k, v := range before {
		if after[k] != v {
			t.Errorf("tombstoned row %s changed: before=%v after=%v", k, v, after[k])
		}
	}
}

func TestUpsertFinding_BeltAndSuspenders_TombstoneGuard(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	now := time.Now().UTC().Truncate(time.Microsecond)
	fp := fmt.Sprintf("fp-belt-%d", now.UnixNano())
	baseID := fmt.Sprintf("finding-belt-%d", now.UnixNano())

	if _, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now.Add(-time.Hour))); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
        UPDATE findings
           SET status = 'resolved',
               tombstoned = TRUE,
               tombstoned_at = $2,
               tombstoned_by = 'tester',
               tombstoned_reason = 'closeout',
               tombstoned_run_id = 'run-belt',
               prior_status = 'open',
               tombstone_generation = 0
         WHERE id = $1`, baseID, now.Add(-30*time.Minute)); err != nil {
		t.Fatalf("tombstone seed: %v", err)
	}

	if _, err := store.db.ExecContext(ctx, `DROP INDEX IF EXISTS findings_active_fingerprint_uidx`); err != nil {
		t.Fatalf("drop partial index: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(ctx, `
            CREATE UNIQUE INDEX IF NOT EXISTS findings_active_fingerprint_uidx
                ON findings (fingerprint) WHERE tombstoned = FALSE`)
	})

	before := tombstoneRowSnapshot(t, ctx, store, baseID)

	if _, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now)); err != nil {
		t.Fatalf("emit with index dropped: %v", err)
	}

	after := tombstoneRowSnapshot(t, ctx, store, baseID)
	for k, v := range before {
		if after[k] != v {
			t.Errorf("tombstoned row %s changed even without partial index: before=%v after=%v", k, v, after[k])
		}
	}
}

func TestUpsertFinding_GenerationCounterIncrementsAcrossTombstones(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	now := time.Now().UTC().Truncate(time.Microsecond)
	fp := fmt.Sprintf("fp-gen-%d", now.UnixNano())
	baseID := fmt.Sprintf("finding-gen-%d", now.UnixNano())

	first, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now.Add(-3*time.Hour)))
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if first.ID != baseID {
		t.Fatalf("first id = %q, want %q", first.ID, baseID)
	}
	if _, err := store.db.ExecContext(ctx, `
        UPDATE findings SET status='resolved', tombstoned=TRUE, tombstoned_at=$2, tombstoned_by='tester',
                            tombstoned_reason='closeout', tombstoned_run_id='gen-1', prior_status='open',
                            tombstone_generation=0
         WHERE id=$1`, baseID, now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("tombstone first: %v", err)
	}

	second, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now.Add(-time.Hour)))
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	wantSecondID := baseID + "#g1"
	if second.ID != wantSecondID {
		t.Fatalf("second id = %q, want %q", second.ID, wantSecondID)
	}

	var gen int
	if err := store.db.QueryRowContext(ctx, `SELECT tombstone_generation FROM findings WHERE id = $1`, wantSecondID).Scan(&gen); err != nil {
		t.Fatalf("read second generation: %v", err)
	}
	if gen != 1 {
		t.Fatalf("second tombstone_generation = %d, want 1", gen)
	}

	var activeCount int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE fingerprint=$1 AND tombstoned=FALSE`, fp).Scan(&activeCount); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if activeCount != 1 {
		t.Fatalf("active rows = %d, want exactly 1", activeCount)
	}

	if _, err := store.db.ExecContext(ctx, `
        UPDATE findings SET status='resolved', tombstoned=TRUE, tombstoned_at=$2, tombstoned_by='tester',
                            tombstoned_reason='closeout', tombstoned_run_id='gen-2', prior_status='open',
                            tombstone_generation=1
         WHERE id=$1`, wantSecondID, now.Add(-30*time.Minute)); err != nil {
		t.Fatalf("tombstone second: %v", err)
	}

	third, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now))
	if err != nil {
		t.Fatalf("third upsert: %v", err)
	}
	wantThirdID := baseID + "#g2"
	if third.ID != wantThirdID {
		t.Fatalf("third id = %q, want %q", third.ID, wantThirdID)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT tombstone_generation FROM findings WHERE id = $1`, wantThirdID).Scan(&gen); err != nil {
		t.Fatalf("read third generation: %v", err)
	}
	if gen != 2 {
		t.Fatalf("third tombstone_generation = %d, want 2", gen)
	}
	if third.ID == first.ID {
		t.Fatalf("third id %q must differ from first tombstoned row id %q", third.ID, first.ID)
	}
}

func TestUpsertFinding_GenerationCounter_Monotonic(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	now := time.Now().UTC().Truncate(time.Microsecond)
	fp := fmt.Sprintf("fp-mono-%d", now.UnixNano())
	baseID := fmt.Sprintf("finding-mono-%d", now.UnixNano())

	tombstone := func(id string, gen int) {
		if _, err := store.db.ExecContext(ctx, `
            UPDATE findings SET status='resolved', tombstoned=TRUE, tombstoned_at=now(), tombstoned_by='tester',
                                tombstoned_reason='closeout', tombstoned_run_id=$2, prior_status='open',
                                tombstone_generation=$3
             WHERE id=$1`, id, fmt.Sprintf("mono-run-%d", gen), gen); err != nil {
			t.Fatalf("tombstone %s gen=%d: %v", id, gen, err)
		}
	}

	first, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now.Add(-4*time.Hour)))
	if err != nil {
		t.Fatalf("cycle 1 upsert: %v", err)
	}
	tombstone(first.ID, 0)

	second, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now.Add(-3*time.Hour)))
	if err != nil {
		t.Fatalf("cycle 2 upsert: %v", err)
	}
	tombstone(second.ID, 1)

	third, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now.Add(-2*time.Hour)))
	if err != nil {
		t.Fatalf("cycle 3 upsert: %v", err)
	}
	tombstone(third.ID, 2)

	// Last emit produces fresh row at generation 3
	fourth, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now))
	if err != nil {
		t.Fatalf("final upsert: %v", err)
	}
	if fourth.ID != baseID+"#g3" {
		t.Fatalf("final id = %q, want %q", fourth.ID, baseID+"#g3")
	}

	rows, err := store.db.QueryContext(ctx, `SELECT tombstone_generation FROM findings WHERE fingerprint=$1 ORDER BY tombstone_generation`, fp)
	if err != nil {
		t.Fatalf("list generations: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var gens []int
	for rows.Next() {
		var g int
		if err := rows.Scan(&g); err != nil {
			t.Fatalf("scan generation: %v", err)
		}
		gens = append(gens, g)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate generations: %v", err)
	}
	want := []int{0, 1, 2, 3}
	if !slices.Equal(gens, want) {
		t.Fatalf("generations = %v, want %v", gens, want)
	}
}

func TestUpsertFinding_ConcurrentEmitAgainstTombstonedFingerprint(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	now := time.Now().UTC().Truncate(time.Microsecond)
	fp := fmt.Sprintf("fp-race-%d", now.UnixNano())
	baseID := fmt.Sprintf("finding-race-%d", now.UnixNano())

	if _, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now.Add(-time.Hour))); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
        UPDATE findings SET status='resolved', tombstoned=TRUE, tombstoned_at=now(), tombstoned_by='tester',
                            tombstoned_reason='closeout', tombstoned_run_id='race-1', prior_status='open',
                            tombstone_generation=0 WHERE id=$1`, baseID); err != nil {
		t.Fatalf("tombstone seed: %v", err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]error, 2)
	ids := make([]string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			out, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now.Add(time.Duration(idx)*time.Millisecond)))
			if err != nil {
				results[idx] = err
				return
			}
			ids[idx] = out.ID
		}(i)
	}
	close(start)
	wg.Wait()

	// Each call must return successfully OR a recognizable conflict; at least one must succeed.
	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
			continue
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			t.Fatalf("unexpected concurrent upsert error: %v", err)
		}
	}
	if successes == 0 {
		t.Fatalf("both concurrent upserts failed: %v", results)
	}

	var activeCount int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE fingerprint=$1 AND tombstoned=FALSE`, fp).Scan(&activeCount); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if activeCount != 1 {
		t.Fatalf("active rows = %d, want exactly 1 fresh tombstoned=FALSE row", activeCount)
	}

	for _, id := range ids {
		if id == "" {
			continue
		}
		var tombstoned bool
		if err := store.db.QueryRowContext(ctx, `SELECT tombstoned FROM findings WHERE id=$1`, id).Scan(&tombstoned); err != nil {
			t.Fatalf("lookup id %q: %v", id, err)
		}
		if tombstoned {
			t.Fatalf("returned id %q is tombstoned; concurrent emit must yield a fresh row", id)
		}
	}
}

func TestResolveUpsertTarget_TombstoneRace(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	now := time.Now().UTC().Truncate(time.Microsecond)
	fp := fmt.Sprintf("fp-stale-target-%d", now.UnixNano())
	baseID := fmt.Sprintf("finding-stale-target-%d", now.UnixNano())

	if _, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now.Add(-time.Hour))); err != nil {
		t.Fatalf("seed active finding: %v", err)
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin row-lock transaction: %v", err)
	}
	committed := false
	t.Cleanup(func() {
		if !committed {
			_ = tx.Rollback()
		}
	})

	var lockedID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM findings WHERE id = $1 FOR UPDATE`, baseID).Scan(&lockedID); err != nil {
		t.Fatalf("lock active finding: %v", err)
	}
	if lockedID != baseID {
		t.Fatalf("locked id = %q, want %q", lockedID, baseID)
	}

	type upsertResult struct {
		record *ports.FindingRecord
		err    error
	}
	resultCh := make(chan upsertResult, 1)
	go func() {
		record, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now))
		resultCh <- upsertResult{record: record, err: err}
	}()

	waitForBlockedFindingUpsert(t, ctx, store)

	if _, err := tx.ExecContext(ctx, `
        UPDATE findings
           SET status = 'resolved',
               tombstoned = TRUE,
               tombstoned_at = $2,
               tombstoned_by = 'tester',
               tombstoned_reason = 'closeout-race',
               tombstoned_run_id = 'race-stale-target',
               prior_status = 'open',
               tombstone_generation = 0
         WHERE id = $1`, baseID, now.Add(-30*time.Minute)); err != nil {
		t.Fatalf("tombstone locked finding: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tombstone race transaction: %v", err)
	}
	committed = true

	var result upsertResult
	select {
	case result = <-resultCh:
	case <-time.After(5 * time.Second):
		t.Fatal("UpsertFinding did not return after tombstone race commit")
	}
	if result.err != nil {
		t.Fatalf("UpsertFinding after tombstone race returned error: %v", result.err)
	}
	if result.record == nil {
		t.Fatal("UpsertFinding after tombstone race returned nil record")
	}
	wantID := baseID + "#g1"
	if result.record.ID != wantID {
		t.Fatalf("post-race id = %q, want fresh generation %q", result.record.ID, wantID)
	}
	if result.record.Tombstoned {
		t.Fatalf("post-race record tombstoned = true, want fresh active row")
	}

	var activeCount int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = 'writer' AND fingerprint = $1 AND tombstoned = FALSE`, fp).Scan(&activeCount); err != nil {
		t.Fatalf("count active rows: %v", err)
	}
	if activeCount != 1 {
		t.Fatalf("active rows after tombstone race = %d, want exactly one fresh generation row", activeCount)
	}

	var baseTombstoned bool
	if err := store.db.QueryRowContext(ctx, `SELECT tombstoned FROM findings WHERE id = $1`, baseID).Scan(&baseTombstoned); err != nil {
		t.Fatalf("read base tombstone flag: %v", err)
	}
	if !baseTombstoned {
		t.Fatalf("base row tombstoned = false, want true")
	}
}

func waitForBlockedFindingUpsert(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		err := store.db.QueryRowContext(ctx, `
SELECT count(*)
  FROM pg_stat_activity
 WHERE datname = current_database()
   AND pid <> pg_backend_pid()
   AND wait_event_type = 'Lock'
   AND query LIKE '%INSERT INTO findings%'`).Scan(&waiting)
		if err == nil && waiting > 0 {
			return
		}
		if err != nil {
			t.Logf("poll pg_stat_activity for blocked upsert: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for UpsertFinding to block on the stale active row")
}

func TestFindingRow_PopulatesTombstoneColumns(t *testing.T) {
	ctx := context.Background()
	store := tombstoneStoreFromEnv(t)
	resetTombstoneSchema(t, ctx, store)
	ensureTombstoneSchema(t, ctx, store)

	now := time.Now().UTC().Truncate(time.Microsecond)
	fp := fmt.Sprintf("fp-record-tombstone-%d", now.UnixNano())
	baseID := fmt.Sprintf("finding-record-tombstone-%d", now.UnixNano())

	if _, err := store.UpsertFinding(ctx, newUpsertFinding(baseID, fp, "open", now.Add(-2*time.Hour))); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	tombstonedAt := now.Add(-time.Hour)
	wantTombstone := ports.FindingTombstone{
		Tombstoned:          true,
		TombstonedAt:        tombstonedAt,
		TombstonedBy:        "alice@writer.com",
		TombstonedReason:    "closeout: pre-conversion backlog",
		TombstonedRunID:     "run-record-tombstone-1",
		PriorStatus:         "open",
		TombstoneGeneration: 3,
	}
	if _, err := store.db.ExecContext(ctx, `
        UPDATE findings
           SET status = 'resolved',
               tombstoned = $2,
               tombstoned_at = $3,
               tombstoned_by = $4,
               tombstoned_reason = $5,
               tombstoned_run_id = $6,
               prior_status = $7,
               tombstone_generation = $8
         WHERE id = $1`,
		baseID,
		wantTombstone.Tombstoned,
		wantTombstone.TombstonedAt,
		wantTombstone.TombstonedBy,
		wantTombstone.TombstonedReason,
		wantTombstone.TombstonedRunID,
		wantTombstone.PriorStatus,
		wantTombstone.TombstoneGeneration,
	); err != nil {
		t.Fatalf("apply tombstone columns: %v", err)
	}

	record, err := store.GetFinding(ctx, baseID)
	if err != nil {
		t.Fatalf("GetFinding(%q): %v", baseID, err)
	}

	if got := record.Tombstoned; got != wantTombstone.Tombstoned {
		t.Errorf("FindingRecord.Tombstoned = %v, want %v", got, wantTombstone.Tombstoned)
	}
	if got := record.TombstonedAt; !got.Equal(wantTombstone.TombstonedAt) {
		t.Errorf("FindingRecord.TombstonedAt = %v, want %v", got, wantTombstone.TombstonedAt)
	}
	if got := record.TombstonedBy; got != wantTombstone.TombstonedBy {
		t.Errorf("FindingRecord.TombstonedBy = %q, want %q", got, wantTombstone.TombstonedBy)
	}
	if got := record.TombstonedReason; got != wantTombstone.TombstonedReason {
		t.Errorf("FindingRecord.TombstonedReason = %q, want %q", got, wantTombstone.TombstonedReason)
	}
	if got := record.TombstonedRunID; got != wantTombstone.TombstonedRunID {
		t.Errorf("FindingRecord.TombstonedRunID = %q, want %q", got, wantTombstone.TombstonedRunID)
	}
	if got := record.PriorStatus; got != wantTombstone.PriorStatus {
		t.Errorf("FindingRecord.PriorStatus = %q, want %q", got, wantTombstone.PriorStatus)
	}
	if got := record.TombstoneGeneration; got != wantTombstone.TombstoneGeneration {
		t.Errorf("FindingRecord.TombstoneGeneration = %d, want %d", got, wantTombstone.TombstoneGeneration)
	}

	listed, err := store.ListFindings(ctx, ports.ListFindingsRequest{
		TenantID:  "writer",
		RuntimeID: "runtime-test",
	})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	var found *ports.FindingRecord
	for _, r := range listed {
		if r.ID == baseID {
			found = r
			break
		}
	}
	if found == nil {
		t.Fatalf("ListFindings did not return seeded finding %q", baseID)
	}
	if found.Tombstoned != wantTombstone.Tombstoned ||
		!found.TombstonedAt.Equal(wantTombstone.TombstonedAt) ||
		found.TombstonedBy != wantTombstone.TombstonedBy ||
		found.TombstonedReason != wantTombstone.TombstonedReason ||
		found.TombstonedRunID != wantTombstone.TombstonedRunID ||
		found.PriorStatus != wantTombstone.PriorStatus ||
		found.TombstoneGeneration != wantTombstone.TombstoneGeneration {
		t.Fatalf("ListFindings returned tombstone fields = %+v, want %+v", found.FindingTombstone, wantTombstone)
	}
}
