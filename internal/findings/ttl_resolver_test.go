package findings

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securityevents"
	"github.com/writer/cerebro/internal/workflowevents"
)

type fixedTTLClock struct {
	now time.Time
}

func (c fixedTTLClock) Now() time.Time { return c.now }

type ttlResolverRule struct {
	spec       *cerebrov1.RuleSpec
	definition RuleDefinition
}

func (r *ttlResolverRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return r.spec
}

func (r *ttlResolverRule) SupportsRuntime(*cerebrov1.SourceRuntime) bool { return false }

func (r *ttlResolverRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *ttlResolverRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

type ttlResolverFixture struct {
	service   *Service
	store     *stubFindingStore
	rule      *ttlResolverRule
	ruleID    string
	tenantID  string
	runtimeID string
	now       time.Time
	logBuf    *bytes.Buffer
}

func newTTLResolverFixture(t *testing.T, kind LifecycleKind, ttl time.Duration) *ttlResolverFixture {
	t.Helper()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	ruleID := "ttl-evidence-rule"
	rule := &ttlResolverRule{
		spec: &cerebrov1.RuleSpec{Id: ruleID, Name: "TTL Evidence Rule"},
		definition: RuleDefinition{
			ID:                ruleID,
			Name:              "TTL Evidence Rule",
			SourceID:          "test-source",
			OutputKind:        "finding.test",
			Severity:          "MEDIUM",
			Status:            "active",
			Maturity:          "ga",
			Runbook:           "https://docs.example/runbook",
			Tags:              []string{"test"},
			References:        []string{"https://docs.example/ref"},
			FalsePositives:    []string{"fp"},
			FingerprintFields: []string{"resource_urn"},
			ControlRefs:       []ports.FindingControlRef{{FrameworkName: "test", ControlID: "T-1"}},
			Lifecycle:         Lifecycle{Kind: kind, TTL: ttl, Anchor: AnchorNone},
		},
	}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{},
		claims:   map[string]*ports.ClaimRecord{},
	}
	runtimeStore := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{}}
	logBuf := &bytes.Buffer{}
	service := NewWithRegistry(runtimeStore, &stubReplayer{}, store, store, store, store, registry).
		WithTTLClock(fixedTTLClock{now: now}).
		WithTTLLogSink(logBuf)

	return &ttlResolverFixture{
		service:   service,
		store:     store,
		rule:      rule,
		ruleID:    ruleID,
		tenantID:  "tenant-a",
		runtimeID: "tenant-a-source",
		now:       now,
		logBuf:    logBuf,
	}
}

//nolint:unparam // Helper keeps status explicit so TTL test fixtures read like production records.
func (f *ttlResolverFixture) seedFinding(id, status string, lastObserved time.Time, mutate func(*ports.FindingRecord)) *ports.FindingRecord {
	finding := &ports.FindingRecord{
		ID:              id,
		Fingerprint:     "fp-" + id,
		TenantID:        f.tenantID,
		RuntimeID:       f.runtimeID,
		RuleID:          f.ruleID,
		Title:           "T " + id,
		Severity:        "MEDIUM",
		Status:          status,
		Summary:         "S " + id,
		ResourceURNs:    []string{"urn:cerebro:tenant-a:resource:" + id},
		EventIDs:        []string{"event-" + id},
		FirstObservedAt: lastObserved.Add(-24 * time.Hour),
		LastObservedAt:  lastObserved,
	}
	if mutate != nil {
		mutate(finding)
	}
	cloned := cloneFinding(finding)
	f.store.findings[cloned.ID] = cloned
	return cloneFinding(cloned)
}

func TestResolveTTLOpenFindings_ResolvesStale(t *testing.T) {
	fx := newTTLResolverFixture(t, LifecycleTTLEvidence, 24*time.Hour)
	fx.seedFinding("stale-1", findingStatusOpen, fx.now.Add(-48*time.Hour), nil)
	fx.seedFinding("stale-2", findingStatusOpen, fx.now.Add(-25*time.Hour), nil)
	fx.seedFinding("fresh-1", findingStatusOpen, fx.now.Add(-6*time.Hour), nil)
	fx.seedFinding("fresh-edge", findingStatusOpen, fx.now.Add(-24*time.Hour), nil)

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.tenantID, fx.ruleID); err != nil {
		t.Fatalf("resolveTTLOpenFindings: %v", err)
	}

	wantResolved := map[string]bool{"stale-1": true, "stale-2": true}
	wantOpen := map[string]bool{"fresh-1": true, "fresh-edge": true}
	for id := range wantResolved {
		f := fx.store.findings[id]
		if f.Status != findingStatusResolved {
			t.Fatalf("finding %q status = %q, want resolved", id, f.Status)
		}
		if f.StatusReason != "ttl_expired:24h" {
			t.Fatalf("finding %q resolution_reason = %q, want ttl_expired:24h", id, f.StatusReason)
		}
		if f.Tombstoned {
			t.Fatalf("finding %q tombstoned after TTL resolve, want false", id)
		}
		if f.StatusUpdatedAt.IsZero() {
			t.Fatalf("finding %q status_updated_at is zero", id)
		}
	}
	for id := range wantOpen {
		f := fx.store.findings[id]
		if f.Status != findingStatusOpen {
			t.Fatalf("fresh finding %q status = %q, want open (last_observed_at=%v cutoff=%v)",
				id, f.Status, f.LastObservedAt, fx.now.Add(-24*time.Hour))
		}
		if f.StatusReason != "" {
			t.Fatalf("fresh finding %q status_reason = %q, want empty", id, f.StatusReason)
		}
	}
}

func TestResolveTTLOpenFindings_EmitsStatusChangedWorkflowEvent(t *testing.T) {
	fx := newTTLResolverFixture(t, LifecycleTTLEvidence, 24*time.Hour)
	appendLog := &recordingAppendLog{}
	fx.service.WithGraphStore(&stubGraphStore{}).WithAppendLog(appendLog)
	fx.seedFinding("stale-event-1", findingStatusOpen, fx.now.Add(-48*time.Hour), nil)
	fx.seedFinding("stale-event-2", findingStatusOpen, fx.now.Add(-30*time.Hour), nil)
	fx.seedFinding("stale-event-3", findingStatusOpen, fx.now.Add(-25*time.Hour), nil)
	fx.seedFinding("fresh-event", findingStatusOpen, fx.now.Add(-6*time.Hour), nil)

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.tenantID, fx.ruleID); err != nil {
		t.Fatalf("resolveTTLOpenFindings: %v", err)
	}

	payloads := decodeStatusChangedPayloads(t, appendLog.events)
	if got, want := len(payloads), 3; got != want {
		t.Fatalf("status_changed event count = %d, want %d (events=%#v)", got, want, eventKinds(appendLog.events))
	}
	wantIDs := map[string]bool{
		"stale-event-1": false,
		"stale-event-2": false,
		"stale-event-3": false,
	}
	for _, payload := range payloads {
		findingID := strings.TrimSpace(payload.Finding.FindingID)
		if _, ok := wantIDs[findingID]; !ok {
			t.Fatalf("status_changed finding_id = %q, want one of %v", findingID, wantIDs)
		}
		wantIDs[findingID] = true
		if got := strings.TrimSpace(payload.Status); got != findingStatusResolved {
			t.Fatalf("status_changed status for %q = %q, want %q", findingID, got, findingStatusResolved)
		}
		if got := strings.TrimSpace(payload.Source); got != workflowevents.FindingStatusSourceStaleEvaluation {
			t.Fatalf("status_changed source for %q = %q, want %q", findingID, got, workflowevents.FindingStatusSourceStaleEvaluation)
		}
	}
	for id, seen := range wantIDs {
		if !seen {
			t.Fatalf("missing status_changed event for TTL-resolved finding %q", id)
		}
	}
}

func TestResolveTTLOpenFindings_StatusChangedPayloadReason(t *testing.T) {
	fx := newTTLResolverFixture(t, LifecycleTTLEvidence, 24*time.Hour)
	appendLog := &recordingAppendLog{}
	fx.service.WithGraphStore(&stubGraphStore{}).WithAppendLog(appendLog)
	fx.seedFinding("stale-reason-1", findingStatusOpen, fx.now.Add(-48*time.Hour), nil)
	fx.seedFinding("stale-reason-2", findingStatusOpen, fx.now.Add(-25*time.Hour), nil)

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.tenantID, fx.ruleID); err != nil {
		t.Fatalf("resolveTTLOpenFindings: %v", err)
	}

	payloads := decodeStatusChangedPayloads(t, appendLog.events)
	if got, want := len(payloads), 2; got != want {
		t.Fatalf("status_changed event count = %d, want %d (events=%#v)", got, want, eventKinds(appendLog.events))
	}
	for _, payload := range payloads {
		findingID := strings.TrimSpace(payload.Finding.FindingID)
		persisted := fx.store.findings[findingID]
		if persisted == nil {
			t.Fatalf("persisted finding %q missing", findingID)
		}
		if got, want := strings.TrimSpace(payload.Reason), "ttl_expired:24h"; got != want {
			t.Fatalf("status_changed reason for %q = %q, want %q", findingID, got, want)
		}
		if got, want := strings.TrimSpace(payload.Reason), strings.TrimSpace(persisted.StatusReason); got != want {
			t.Fatalf("status_changed reason for %q = %q, want persisted status_reason %q", findingID, got, want)
		}
	}
}

func TestResolveTTLOpenFindings_NoOpForNonTTLRules(t *testing.T) {
	fx := newTTLResolverFixture(t, LifecycleAuditEvidence, 0)
	fx.seedFinding("f-1", findingStatusOpen, fx.now.Add(-48*time.Hour), nil)
	fx.seedFinding("f-2", findingStatusOpen, fx.now.Add(-72*time.Hour), nil)

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.tenantID, fx.ruleID); err != nil {
		t.Fatalf("resolveTTLOpenFindings: %v", err)
	}
	if fx.store.updateStatusCallCount != 0 {
		t.Fatalf("non-ttl rule produced %d UpdateFindingStatus calls, want 0", fx.store.updateStatusCallCount)
	}
	for id, finding := range fx.store.findings {
		if finding.Status != findingStatusOpen {
			t.Fatalf("finding %q status = %q, want open (non-ttl rule must not mutate)", id, finding.Status)
		}
		if finding.StatusReason != "" {
			t.Fatalf("finding %q status_reason = %q, want empty", id, finding.StatusReason)
		}
	}
}

func TestResolveTTLOpenFindings_LeavesTombstonedAlone(t *testing.T) {
	fx := newTTLResolverFixture(t, LifecycleTTLEvidence, 24*time.Hour)
	tombstonedAt := fx.now.Add(-30 * time.Hour)
	fx.seedFinding("tombstoned-stale", findingStatusOpen, fx.now.Add(-48*time.Hour), func(f *ports.FindingRecord) {
		f.FindingTombstone = ports.FindingTombstone{
			Tombstoned:          true,
			TombstonedAt:        tombstonedAt,
			TombstonedBy:        "operator",
			TombstonedReason:    "bulk closeout",
			TombstonedRunID:     "run-prev",
			PriorStatus:         findingStatusOpen,
			TombstoneGeneration: 1,
		}
	})
	fx.seedFinding("active-stale", findingStatusOpen, fx.now.Add(-48*time.Hour), nil)
	before := cloneFinding(fx.store.findings["tombstoned-stale"])

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.tenantID, fx.ruleID); err != nil {
		t.Fatalf("resolveTTLOpenFindings: %v", err)
	}

	after := fx.store.findings["tombstoned-stale"]
	if !after.Tombstoned {
		t.Fatalf("tombstoned row flipped Tombstoned=false")
	}
	if after.Status != before.Status {
		t.Fatalf("tombstoned row status changed: before=%q after=%q", before.Status, after.Status)
	}
	if after.StatusReason != before.StatusReason {
		t.Fatalf("tombstoned row status_reason changed: before=%q after=%q", before.StatusReason, after.StatusReason)
	}
	if !after.TombstonedAt.Equal(before.TombstonedAt) {
		t.Fatalf("tombstoned_at changed: before=%v after=%v", before.TombstonedAt, after.TombstonedAt)
	}
	if after.TombstonedBy != before.TombstonedBy ||
		after.TombstonedReason != before.TombstonedReason ||
		after.TombstonedRunID != before.TombstonedRunID ||
		after.PriorStatus != before.PriorStatus ||
		after.TombstoneGeneration != before.TombstoneGeneration {
		t.Fatalf("tombstone columns mutated by TTL sweep: before=%+v after=%+v", before.FindingTombstone, after.FindingTombstone)
	}

	active := fx.store.findings["active-stale"]
	if active.Status != findingStatusResolved {
		t.Fatalf("active stale row status = %q, want resolved", active.Status)
	}
	if active.StatusReason != "ttl_expired:24h" {
		t.Fatalf("active stale row status_reason = %q, want ttl_expired:24h", active.StatusReason)
	}
}

func TestResolveTTLOpenFindings_ReopenOnEmit(t *testing.T) {
	fx := newTTLResolverFixture(t, LifecycleTTLEvidence, 24*time.Hour)
	original := fx.seedFinding("ttl-reopen", findingStatusOpen, fx.now.Add(-48*time.Hour), nil)

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.tenantID, fx.ruleID); err != nil {
		t.Fatalf("resolveTTLOpenFindings: %v", err)
	}

	resolved := fx.store.findings[original.ID]
	if resolved.Status != findingStatusResolved {
		t.Fatalf("post-TTL status = %q, want resolved", resolved.Status)
	}
	if resolved.StatusReason != "ttl_expired:24h" {
		t.Fatalf("post-TTL status_reason = %q, want ttl_expired:24h", resolved.StatusReason)
	}
	if resolved.Tombstoned {
		t.Fatalf("TTL sweep tombstoned the row (must allow reopen-on-emit)")
	}

	// Mirror the postgres reopen-on-emit CASE: a fresh emit against a
	// non-tombstoned resolved row flips status back to open in place and
	// preserves the row id. The stub's UpdateFindingStatus is the same per-row
	// write path the postgres CASE drives the flip through.
	reemitAt := fx.now.Add(time.Hour)
	reopened, err := fx.store.UpdateFindingStatus(context.Background(), ports.FindingStatusUpdate{
		FindingID: original.ID,
		Status:    findingStatusOpen,
		UpdatedAt: reemitAt,
	})
	if err != nil {
		t.Fatalf("reopen UpdateFindingStatus: %v", err)
	}
	if reopened.ID != original.ID {
		t.Fatalf("reopened id = %q, want unchanged %q", reopened.ID, original.ID)
	}
	if reopened.Status != findingStatusOpen {
		t.Fatalf("reopened status = %q, want open", reopened.Status)
	}
	if reopened.Tombstoned {
		t.Fatalf("reopened Tombstoned = true, want false")
	}
}

func TestEvaluateSourceRuntimeRules_TTLEvidenceListFindingsUsesTenantScope(t *testing.T) {
	openedAt := identityTrajectoryBaseTime
	identityRule := identityRulesByID(t)[identityAuthControlLifecycleTamperingRuleID]
	identityRuntime := &cerebrov1.SourceRuntime{Id: "example-okta-audit", SourceId: "okta", TenantId: "writer"}
	identityEvent := identitySignalEventAt("okta-policy-weakened-tenant-scope", "okta", "okta.audit", map[string]string{
		"domain":                "writer.okta.com",
		"event_type":            "policy.lifecycle.update",
		"actor_email":           "admin@writer.com",
		"policy_id":             "pol-sign-on",
		"resource_id":           "pol-sign-on",
		"resource_type":         "policy",
		"auth_control_weakened": "true",
		"outcome_result":        "SUCCESS",
	}, openedAt)

	cases := []struct {
		name    string
		rule    Rule
		ruleID  string
		runtime *cerebrov1.SourceRuntime
		events  []*cerebrov1.EventEnvelope
	}{
		{
			name:    "runtime active threat evidence",
			rule:    newRuntimeActiveThreatEvidenceRule(),
			ruleID:  runtimeActiveThreatEvidenceRuleID,
			runtime: &cerebrov1.SourceRuntime{Id: "runtime-prod", SourceId: "runtime", TenantId: "writer"},
			events:  []*cerebrov1.EventEnvelope{runtimeActiveThreatTTLEvent(openedAt)},
		},
		{
			name:    "identity auth control lifecycle tampering",
			rule:    identityRule,
			ruleID:  identityAuthControlLifecycleTamperingRuleID,
			runtime: identityRuntime,
			events:  []*cerebrov1.EventEnvelope{identityEvent},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry, err := NewRegistry(tc.rule)
			if err != nil {
				t.Fatalf("NewRegistry(%q) error = %v", tc.ruleID, err)
			}
			store := &tenantRequiredListFindingStore{stubFindingStore: &stubFindingStore{}}
			replayer := &stubReplayer{events: tc.events}
			service := NewWithRegistry(
				&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
					tc.runtime.GetId(): tc.runtime,
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

			if _, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
				RuntimeID: tc.runtime.GetId(),
				RuleIDs:   []string{tc.ruleID},
			}); err != nil {
				t.Fatalf("EvaluateSourceRuntimeRules(%q) error = %v", tc.ruleID, err)
			}

			request, ok := lastListFindingsRequestForRule(store.listFindingsRequests, tc.ruleID)
			if !ok {
				t.Fatalf("ListFindings was not called for ttl_evidence rule %q; requests=%+v", tc.ruleID, store.listFindingsRequests)
			}
			if got := strings.TrimSpace(request.TenantID); got != strings.TrimSpace(tc.runtime.GetTenantId()) {
				t.Fatalf("TTL ListFindings TenantID = %q, want %q (request=%+v)", got, tc.runtime.GetTenantId(), request)
			}
			if got := strings.TrimSpace(request.RuleID); got != tc.ruleID {
				t.Fatalf("TTL ListFindings RuleID = %q, want %q", got, tc.ruleID)
			}
			if got := strings.TrimSpace(request.Status); got != findingStatusOpen {
				t.Fatalf("TTL ListFindings Status = %q, want %q", got, findingStatusOpen)
			}
		})
	}
}

func lastListFindingsRequestForRule(requests []ports.ListFindingsRequest, ruleID string) (ports.ListFindingsRequest, bool) {
	for i := len(requests) - 1; i >= 0; i-- {
		if strings.TrimSpace(requests[i].RuleID) == strings.TrimSpace(ruleID) {
			return requests[i], true
		}
	}
	return ports.ListFindingsRequest{}, false
}

type tenantRequiredListFindingStore struct {
	*stubFindingStore
}

func (s *tenantRequiredListFindingStore) ListFindings(ctx context.Context, request ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	if strings.TrimSpace(request.TenantID) == "" {
		s.request = request
		s.listFindingsRequests = append(s.listFindingsRequests, request)
		return nil, errors.New("finding tenant id is required")
	}
	return s.stubFindingStore.ListFindings(ctx, request)
}

func TestResolveTTLOpenFindings_Idempotent(t *testing.T) {
	fx := newTTLResolverFixture(t, LifecycleTTLEvidence, 24*time.Hour)
	fx.seedFinding("stale-1", findingStatusOpen, fx.now.Add(-48*time.Hour), nil)
	fx.seedFinding("stale-2", findingStatusOpen, fx.now.Add(-30*time.Hour), nil)
	fx.seedFinding("fresh-1", findingStatusOpen, fx.now.Add(-6*time.Hour), nil)

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.tenantID, fx.ruleID); err != nil {
		t.Fatalf("first resolveTTLOpenFindings: %v", err)
	}
	firstCallCount := fx.store.updateStatusCallCount
	if firstCallCount == 0 {
		t.Fatalf("first sweep performed zero updates; nothing to verify idempotency against")
	}

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.tenantID, fx.ruleID); err != nil {
		t.Fatalf("second resolveTTLOpenFindings: %v", err)
	}
	if fx.store.updateStatusCallCount != firstCallCount {
		t.Fatalf("second sweep added %d UpdateFindingStatus calls, want 0 (idempotent)",
			fx.store.updateStatusCallCount-firstCallCount)
	}
}

func TestResolveTTLOpenFindings_StructuredLog(t *testing.T) {
	fx := newTTLResolverFixture(t, LifecycleTTLEvidence, 24*time.Hour)
	stale := fx.seedFinding("stale-log-1", findingStatusOpen, fx.now.Add(-48*time.Hour), nil)
	other := fx.seedFinding("stale-log-2", findingStatusOpen, fx.now.Add(-25*time.Hour), nil)
	fx.seedFinding("fresh-log", findingStatusOpen, fx.now.Add(-6*time.Hour), nil)

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.tenantID, fx.ruleID); err != nil {
		t.Fatalf("resolveTTLOpenFindings: %v", err)
	}

	lines := splitLogLines(fx.logBuf.String())
	if len(lines) != 2 {
		t.Fatalf("structured log line count = %d, want 2 (for two resolved findings); raw=%q",
			len(lines), fx.logBuf.String())
	}
	wantIDs := map[string]bool{stale.ID: false, other.ID: false}
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line is not valid JSON: %q (err=%v)", line, err)
		}
		if entry["event"] != "ttl.resolve" {
			t.Fatalf("log entry event = %v, want ttl.resolve", entry["event"])
		}
		if entry["rule_id"] != fx.ruleID {
			t.Fatalf("log entry rule_id = %v, want %q", entry["rule_id"], fx.ruleID)
		}
		if entry["ttl"] != "24h" {
			t.Fatalf("log entry ttl = %v, want 24h", entry["ttl"])
		}
		findingID, _ := entry["finding_id"].(string)
		if _, ok := wantIDs[findingID]; !ok {
			t.Fatalf("log entry finding_id = %q, not in expected set %v", findingID, wantIDs)
		}
		wantIDs[findingID] = true
		resolvedAt, _ := entry["resolved_at"].(string)
		if resolvedAt == "" {
			t.Fatalf("log entry missing resolved_at: %q", line)
		}
		if _, err := time.Parse(time.RFC3339Nano, resolvedAt); err != nil {
			t.Fatalf("log entry resolved_at not RFC3339Nano: %q (err=%v)", resolvedAt, err)
		}
	}
	for id, seen := range wantIDs {
		if !seen {
			t.Fatalf("expected log entry for finding %q, none seen", id)
		}
	}
}

func TestResolveRuleOpenFindings_InvokesTTLResolverForTTLEvidence(t *testing.T) {
	fx := newTTLResolverFixture(t, LifecycleTTLEvidence, 24*time.Hour)
	runtime := &cerebrov1.SourceRuntime{Id: fx.runtimeID, TenantId: fx.tenantID}
	stale := fx.seedFinding("stale-ttl", findingStatusOpen, fx.now.Add(-48*time.Hour), nil)
	fresh := fx.seedFinding("fresh-ttl", findingStatusOpen, fx.now.Add(-6*time.Hour), nil)

	if _, err := fx.service.resolveRuleOpenFindings(context.Background(), runtime, fx.rule, nil, nil, nil); err != nil {
		t.Fatalf("resolveRuleOpenFindings: %v", err)
	}

	resolved := fx.store.findings[stale.ID]
	if resolved.Status != findingStatusResolved {
		t.Fatalf("ttl_evidence stale finding status = %q, want resolved (TTL resolver must have been invoked)", resolved.Status)
	}
	if resolved.StatusReason != "ttl_expired:24h" {
		t.Fatalf("ttl_evidence stale finding reason = %q, want ttl_expired:24h", resolved.StatusReason)
	}

	freshAfter := fx.store.findings[fresh.ID]
	if freshAfter.Status != findingStatusOpen {
		t.Fatalf("ttl_evidence fresh finding status = %q, want open (within TTL window)", freshAfter.Status)
	}

	lines := splitLogLines(fx.logBuf.String())
	if len(lines) != 1 {
		t.Fatalf("ttl.resolve log line count = %d, want 1; raw=%q", len(lines), fx.logBuf.String())
	}

	fx.store.updateStatusCalls = nil
	callsBefore := fx.store.updateStatusCallCount
	if _, err := fx.service.resolveRuleOpenFindings(context.Background(), runtime, fx.rule, nil, nil, nil); err != nil {
		t.Fatalf("second resolveRuleOpenFindings: %v", err)
	}
	if fx.store.updateStatusCallCount != callsBefore {
		t.Fatalf("second resolveRuleOpenFindings performed %d additional UpdateFindingStatus calls, want 0 (idempotent)",
			fx.store.updateStatusCallCount-callsBefore)
	}
}

func TestResolveRuleOpenFindings_SkipsTTLResolverForNonTTLRules(t *testing.T) {
	fx := newTTLResolverFixture(t, LifecycleAuditEvidence, 0)
	runtime := &cerebrov1.SourceRuntime{Id: fx.runtimeID, TenantId: fx.tenantID}
	fx.seedFinding("aged-audit", findingStatusOpen, fx.now.Add(-48*time.Hour), nil)

	if _, err := fx.service.resolveRuleOpenFindings(context.Background(), runtime, fx.rule, nil, nil, nil); err != nil {
		t.Fatalf("resolveRuleOpenFindings: %v", err)
	}

	for id, finding := range fx.store.findings {
		if strings.HasPrefix(finding.StatusReason, ttlResolutionReasonPrefix) {
			t.Fatalf("non-ttl rule produced ttl_expired status reason on finding %q: %q", id, finding.StatusReason)
		}
	}
	if got := fx.logBuf.Len(); got != 0 {
		t.Fatalf("non-ttl rule wrote %d bytes to TTL log sink, want 0: %q", got, fx.logBuf.String())
	}
}

func splitLogLines(s string) []string {
	out := []string{}
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func decodeStatusChangedPayloads(t *testing.T, events []*cerebrov1.EventEnvelope) []*workflowevents.FindingStatusChanged {
	t.Helper()
	payloads := make([]*workflowevents.FindingStatusChanged, 0, len(events))
	for i, event := range events {
		decodeEvent := event
		if event.GetKind() == securityevents.FindingStatusChanged {
			decodeEvent = protoCloneEvent(event, workflowevents.EventKindFindingStatusChanged)
		} else if event.GetKind() != workflowevents.EventKindFindingStatusChanged {
			t.Fatalf("appendLog.events[%d].Kind = %q, want %q", i, event.GetKind(), securityevents.FindingStatusChanged)
		}
		payload, err := workflowevents.DecodeFindingStatusChanged(decodeEvent)
		if err != nil {
			t.Fatalf("DecodeFindingStatusChanged(events[%d]): %v", i, err)
		}
		payloads = append(payloads, payload)
	}
	return payloads
}

func eventKinds(events []*cerebrov1.EventEnvelope) []string {
	kinds := make([]string, 0, len(events))
	for _, event := range events {
		kinds = append(kinds, event.GetKind())
	}
	return kinds
}
