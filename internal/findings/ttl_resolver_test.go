package findings

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
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

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.ruleID); err != nil {
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

func TestResolveTTLOpenFindings_NoOpForNonTTLRules(t *testing.T) {
	fx := newTTLResolverFixture(t, LifecycleAuditEvidence, 0)
	fx.seedFinding("f-1", findingStatusOpen, fx.now.Add(-48*time.Hour), nil)
	fx.seedFinding("f-2", findingStatusOpen, fx.now.Add(-72*time.Hour), nil)

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.ruleID); err != nil {
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

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.ruleID); err != nil {
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

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.ruleID); err != nil {
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

func TestResolveTTLOpenFindings_Idempotent(t *testing.T) {
	fx := newTTLResolverFixture(t, LifecycleTTLEvidence, 24*time.Hour)
	fx.seedFinding("stale-1", findingStatusOpen, fx.now.Add(-48*time.Hour), nil)
	fx.seedFinding("stale-2", findingStatusOpen, fx.now.Add(-30*time.Hour), nil)
	fx.seedFinding("fresh-1", findingStatusOpen, fx.now.Add(-6*time.Hour), nil)

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.ruleID); err != nil {
		t.Fatalf("first resolveTTLOpenFindings: %v", err)
	}
	firstCallCount := fx.store.updateStatusCallCount
	if firstCallCount == 0 {
		t.Fatalf("first sweep performed zero updates; nothing to verify idempotency against")
	}

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.ruleID); err != nil {
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

	if err := fx.service.resolveTTLOpenFindings(context.Background(), fx.ruleID); err != nil {
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
