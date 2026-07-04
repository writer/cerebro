package findings

import (
	"context"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRuntimeActiveThreatEvidenceRule(t *testing.T) {
	rule := newRuntimeActiveThreatEvidenceRule()
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-prod", SourceId: "runtime", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "runtime-evidence-1",
		TenantId: "writer",
		SourceId: "runtime",
		Kind:     "runtime.evidence",
		Attributes: map[string]string{
			"confidence":    "0.92",
			"evidence_id":   "evidence-1",
			"evidence_type": "credential_use",
			"resource_urn":  "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:workload-1",
			"verdict":       "confirmed",
		},
	}
	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:runtime_evidence:evidence-1")
	originalFingerprint := records[0].Fingerprint

	reemit := &cerebrov1.EventEnvelope{
		Id:         "runtime-evidence-1-reemit",
		TenantId:   "writer",
		SourceId:   "runtime",
		Kind:       "runtime.evidence",
		Attributes: event.GetAttributes(),
	}
	records, err = rule.Evaluate(context.Background(), runtime, reemit)
	if err != nil {
		t.Fatalf("Evaluate(reemit) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(reemit records) = %d, want 1", len(records))
	}
	if records[0].Fingerprint != originalFingerprint {
		t.Fatalf("reemit fingerprint = %q, want original %q", records[0].Fingerprint, originalFingerprint)
	}

	benign := &cerebrov1.EventEnvelope{Id: "runtime-evidence-benign", TenantId: "writer", SourceId: "runtime", Kind: "runtime.evidence", Attributes: map[string]string{"confidence": "0.2", "evidence_type": "process_exec", "verdict": "benign"}}
	records, err = rule.Evaluate(context.Background(), runtime, benign)
	if err != nil {
		t.Fatalf("Evaluate(benign) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(benign records) = %d, want 0", len(records))
	}

	inactive := &cerebrov1.EventEnvelope{Id: "runtime-evidence-inactive", TenantId: "writer", SourceId: "runtime", Kind: "runtime.evidence", Attributes: map[string]string{"confidence": "0.2", "evidence_type": "credential_use", "verdict": "inactive"}}
	records, err = rule.Evaluate(context.Background(), runtime, inactive)
	if err != nil {
		t.Fatalf("Evaluate(inactive) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(inactive records) = %d, want 0", len(records))
	}

	activeRisky := &cerebrov1.EventEnvelope{Id: "runtime-evidence-active", TenantId: "writer", SourceId: "runtime", Kind: "runtime.evidence", Attributes: map[string]string{"confidence": "0.2", "evidence_type": "credential_use", "verdict": "active"}}
	records, err = rule.Evaluate(context.Background(), runtime, activeRisky)
	if err != nil {
		t.Fatalf("Evaluate(active) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(active records) = %d, want 1", len(records))
	}

	missingEvidenceType := &cerebrov1.EventEnvelope{Id: "runtime-evidence-missing-evidence-type", TenantId: "example", SourceId: "runtime", Kind: "runtime.evidence", Attributes: map[string]string{"confidence": "0.92", "verdict": "malicious"}}
	records, err = rule.Evaluate(context.Background(), runtime, missingEvidenceType)
	if err != nil {
		t.Fatalf("Evaluate(missing evidence_type) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(missing evidence_type records) = %d, want 0", len(records))
	}
}

func TestRuntimeActiveThreatEvidenceTTL(t *testing.T) {
	const runtimeID = "runtime-prod"
	const tenantID = "writer"
	wantTTL := 24 * time.Hour
	openedAt := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	freshAt := openedAt.Add(23 * time.Hour)
	staleAt := freshAt.Add(wantTTL + time.Hour)
	reemitAt := staleAt.Add(time.Hour)

	rule := newRuntimeActiveThreatEvidenceRule()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("runtime active threat rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if err := definition.Validate(); err != nil {
		t.Fatalf("RuleDefinition.Validate() error = %v", err)
	}
	if definition.Lifecycle.Kind != LifecycleTTLEvidence {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleTTLEvidence)
	}
	if definition.Lifecycle.Anchor != AnchorNone {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorNone)
	}
	if definition.Lifecycle.TTL != wantTTL {
		t.Fatalf("Lifecycle.TTL = %v, want %v", definition.Lifecycle.TTL, wantTTL)
	}

	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry(%q) error = %v", runtimeActiveThreatEvidenceRuleID, err)
	}
	store := &stubFindingStore{}
	replayer := &stubReplayer{events: []*cerebrov1.EventEnvelope{runtimeActiveThreatTTLEvent(openedAt)}}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {Id: runtimeID, SourceId: "runtime", TenantId: tenantID},
		}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	).WithGraphStore(&stubGraphStore{}).
		WithAppendLog(&recordingAppendLog{}).
		WithTTLClock(fixedTTLClock{now: openedAt})

	result, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{runtimeActiveThreatEvidenceRuleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(open) error = %v", err)
	}
	if result == nil || len(result.Evaluations) != 1 {
		t.Fatalf("open result evaluations = %#v, want one", result)
	}
	if got := len(result.Evaluations[0].Findings); got != 1 {
		t.Fatalf("open pass emitted %d findings, want 1", got)
	}
	opened := result.Evaluations[0].Findings[0]
	if got := strings.TrimSpace(opened.Status); got != findingStatusOpen {
		t.Fatalf("opening finding status = %q, want %q", got, findingStatusOpen)
	}
	stored := store.findings[opened.ID]
	if stored == nil {
		t.Fatalf("store missing opened finding %q", opened.ID)
	}
	stored.Assignee = "runtime-analyst@example.com"
	stored.Notes = []ports.FindingNote{{ID: "note-1", Body: "manual runtime note", CreatedAt: openedAt.Add(time.Minute)}}
	stored.Tickets = []ports.FindingTicket{{URL: "https://tickets.example/SEC-123", Name: "SEC-123", ExternalID: "SEC-123", LinkedAt: openedAt.Add(2 * time.Minute)}}

	replayer.events = []*cerebrov1.EventEnvelope{runtimeActiveThreatTTLEvent(freshAt)}
	service.WithTTLClock(fixedTTLClock{now: freshAt})
	if _, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{runtimeActiveThreatEvidenceRuleID},
	}); err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(fresh) error = %v", err)
	}
	fresh := store.findings[opened.ID]
	if fresh == nil {
		t.Fatalf("store missing fresh finding %q", opened.ID)
	}
	if got := strings.TrimSpace(fresh.Status); got != findingStatusOpen {
		t.Fatalf("fresh emit status = %q, want %q", got, findingStatusOpen)
	}
	if !fresh.LastObservedAt.Equal(freshAt) {
		t.Fatalf("fresh emit last_observed_at = %v, want %v", fresh.LastObservedAt, freshAt)
	}
	assertRuntimeActiveThreatTTLManualFields(t, fresh)
	if store.updateStatusCallCount != 0 {
		t.Fatalf("fresh emit within TTL made %d UpdateFindingStatus calls, want 0", store.updateStatusCallCount)
	}

	service.WithTTLClock(fixedTTLClock{now: staleAt})
	if err := service.resolveTTLOpenFindings(context.Background(), tenantID, runtimeActiveThreatEvidenceRuleID); err != nil {
		t.Fatalf("resolveTTLOpenFindings(%q): %v", runtimeActiveThreatEvidenceRuleID, err)
	}
	resolved := store.findings[opened.ID]
	if got := strings.TrimSpace(resolved.Status); got != findingStatusResolved {
		t.Fatalf("TTL-resolved status = %q, want %q", got, findingStatusResolved)
	}
	if got := strings.TrimSpace(resolved.StatusReason); got != "ttl_expired:24h" {
		t.Fatalf("TTL resolution_reason = %q, want ttl_expired:24h", got)
	}
	if resolved.Tombstoned {
		t.Fatal("TTL sweep tombstoned the finding; want resolved without tombstone")
	}
	assertRuntimeActiveThreatTTLManualFields(t, resolved)
	if store.updateStatusCallCount != 1 {
		t.Fatalf("UpdateFindingStatus calls after TTL sweep = %d, want 1", store.updateStatusCallCount)
	}

	// Mirror the production postgres reopen-on-emit CASE for a non-tombstoned
	// ttl-resolved row: a fresh open emit flips the active row back to open in
	// place rather than tombstoning it or minting a replacement. The
	// postgres-backed TestService_TTLEvidenceEvaluateUsesPostgresTenantScopeAndReopens
	// covers this through the real EvaluateSourceRuntimeRules -> UpsertFinding path.
	reopened, err := store.UpdateFindingStatus(context.Background(), ports.FindingStatusUpdate{
		FindingID: opened.ID,
		Status:    findingStatusOpen,
		UpdatedAt: reemitAt,
	})
	if err != nil {
		t.Fatalf("reopen UpdateFindingStatus: %v", err)
	}
	if got := strings.TrimSpace(reopened.Status); got != findingStatusOpen {
		t.Fatalf("reopened status = %q, want %q", got, findingStatusOpen)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("reopened finding id = %q, want unchanged %q", got, opened.ID)
	}
	if got := strings.TrimSpace(reopened.StatusReason); got != "" {
		t.Fatalf("reopened status_reason = %q, want empty", got)
	}
	if !reopened.StatusUpdatedAt.Equal(reemitAt) {
		t.Fatalf("reopened status_updated_at = %v, want %v", reopened.StatusUpdatedAt, reemitAt)
	}
	if reopened.Tombstoned {
		t.Fatal("reopened finding is tombstoned; want non-tombstoned active row")
	}
	assertRuntimeActiveThreatTTLManualFields(t, reopened)
}

func runtimeActiveThreatTTLEvent(observedAt time.Time) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         "runtime-evidence-ttl",
		TenantId:   "writer",
		SourceId:   "runtime",
		Kind:       "runtime.evidence",
		OccurredAt: timestamppb.New(observedAt),
		Attributes: map[string]string{
			"confidence":    "0.95",
			"evidence_id":   "evidence-ttl",
			"evidence_type": "credential_use",
			"resource_urn":  "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:workload-ttl",
			"verdict":       "confirmed",
		},
	}
}

func assertRuntimeActiveThreatTTLManualFields(t *testing.T, finding *ports.FindingRecord) {
	t.Helper()
	if finding == nil {
		t.Fatal("finding is nil")
	}
	if got := strings.TrimSpace(finding.Assignee); got != "runtime-analyst@example.com" {
		t.Fatalf("assignee = %q, want runtime-analyst@example.com", got)
	}
	if len(finding.Notes) != 1 || strings.TrimSpace(finding.Notes[0].Body) != "manual runtime note" {
		t.Fatalf("notes = %#v, want one preserved manual runtime note", finding.Notes)
	}
	if len(finding.Tickets) != 1 || strings.TrimSpace(finding.Tickets[0].ExternalID) != "SEC-123" {
		t.Fatalf("tickets = %#v, want one preserved SEC-123 ticket", finding.Tickets)
	}
}
