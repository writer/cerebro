package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type stubCloseoutStore struct {
	mu   sync.Mutex
	runs map[string]*ports.CloseoutRunRecord
}

func newStubCloseoutStore() *stubCloseoutStore {
	return &stubCloseoutStore{runs: map[string]*ports.CloseoutRunRecord{}}
}

func (s *stubCloseoutStore) InsertCloseoutRun(_ context.Context, run ports.CloseoutRunInsert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.runs[run.RunID]; ok {
		if existing.Status == "running" {
			return ports.ErrCloseoutRunInFlight
		}
		return ports.ErrCloseoutRunAlreadyExists
	}
	for _, existing := range s.runs {
		if existing.Status == "running" {
			return ports.ErrCloseoutRunInFlight
		}
	}
	selector := append([]byte(nil), run.SelectorJSON...)
	s.runs[run.RunID] = &ports.CloseoutRunRecord{
		RunID:        run.RunID,
		Actor:        run.Actor,
		ChangeTicket: run.ChangeTicket,
		SelectorJSON: selector,
		Status:       "running",
		StartedAt:    run.StartedAt,
		DryRun:       run.DryRun,
	}
	return nil
}

func (s *stubCloseoutStore) FinishCloseoutRun(_ context.Context, finish ports.CloseoutRunFinish) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.runs[finish.RunID]
	if !ok {
		return fmt.Errorf("closeout_run %q not found", finish.RunID)
	}
	existing.Status = finish.Status
	existing.FinishedAt = finish.FinishedAt
	existing.ProposedCount = finish.ProposedCount
	existing.AppliedCount = finish.AppliedCount
	existing.ErrorMessage = finish.ErrorMessage
	if finish.S3SummaryKey != "" {
		existing.S3SummaryKey = finish.S3SummaryKey
	}
	return nil
}

func (s *stubCloseoutStore) GetCloseoutRun(_ context.Context, runID string) (*ports.CloseoutRunRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.runs[runID]
	if !ok {
		return nil, fmt.Errorf("closeout_run %q not found", runID)
	}
	clone := *existing
	clone.SelectorJSON = append([]byte(nil), existing.SelectorJSON...)
	return &clone, nil
}

type stubFindingTombstoneEventStore struct {
	mu     sync.Mutex
	events []ports.FindingTombstoneEvent
}

func newStubFindingTombstoneEventStore() *stubFindingTombstoneEventStore {
	return &stubFindingTombstoneEventStore{}
}

func (s *stubFindingTombstoneEventStore) InsertFindingTombstoneEvent(_ context.Context, event ports.FindingTombstoneEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if event.TombstonedAt.IsZero() {
		event.TombstonedAt = time.Now().UTC()
	}
	s.events = append(s.events, event)
	return nil
}

func (s *stubFindingTombstoneEventStore) CountFindingTombstoneEventsByRun(_ context.Context, runID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, event := range s.events {
		if event.RunID == runID {
			count++
		}
	}
	return count, nil
}

func (s *stubFindingTombstoneEventStore) snapshot() []ports.FindingTombstoneEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ports.FindingTombstoneEvent, len(s.events))
	copy(out, s.events)
	return out
}

type closeoutFixture struct {
	service      *Service
	store        *stubFindingStore
	closeout     *stubCloseoutStore
	tombstone    *stubFindingTombstoneEventStore
	appendLog    *recordingAppendLog
	runtimeStore *stubRuntimeStore
	tenantID     string
	ruleID       string
	runtimeID    string
	now          time.Time
}

func newCloseoutFixture(t *testing.T) *closeoutFixture {
	t.Helper()
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{},
		claims:   map[string]*ports.ClaimRecord{},
	}
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"tenant-a-source-a": {
				Id:       "tenant-a-source-a",
				SourceId: "source-a",
				TenantId: "tenant-a",
			},
		},
	}
	closeoutStore := newStubCloseoutStore()
	tombstoneStore := newStubFindingTombstoneEventStore()
	appendLog := &recordingAppendLog{}
	service := New(runtimeStore, &stubReplayer{}, store, store, store, store).
		WithAppendLog(appendLog).
		WithCloseoutStore(closeoutStore).
		WithFindingTombstoneEventStore(tombstoneStore)
	return &closeoutFixture{
		service:      service,
		store:        store,
		closeout:     closeoutStore,
		tombstone:    tombstoneStore,
		appendLog:    appendLog,
		runtimeStore: runtimeStore,
		tenantID:     "tenant-a",
		ruleID:       "rule-critical-resource-deleted",
		runtimeID:    "tenant-a-source-a",
		now:          time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC),
	}
}

func (f *closeoutFixture) seedFinding(id string, status string, lastObserved time.Time, mutate func(*ports.FindingRecord)) *ports.FindingRecord {
	return f.seedFindingWithRule(id, f.ruleID, status, lastObserved, mutate)
}

func (f *closeoutFixture) seedFindingWithRule(id string, ruleID string, status string, lastObserved time.Time, mutate func(*ports.FindingRecord)) *ports.FindingRecord {
	finding := &ports.FindingRecord{
		ID:              id,
		Fingerprint:     "fp-" + id,
		TenantID:        f.tenantID,
		RuntimeID:       f.runtimeID,
		RuleID:          ruleID,
		Title:           "T " + id,
		Severity:        "MEDIUM",
		Status:          status,
		Summary:         "S " + id,
		ResourceURNs:    []string{"urn:cerebro:writer:resource:" + id},
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

func (f *closeoutFixture) request(runID string, dryRun bool) CloseoutRequest {
	return CloseoutRequest{
		Selector: CloseoutSelector{
			TenantID: f.tenantID,
			RuleIDs:  []string{f.ruleID},
		},
		Reason: "bulk closeout: pre-conversion backlog",
		Actor:  "operator@writer.com",
		RunID:  runID,
		DryRun: dryRun,
	}
}

func TestTombstoneFindingsBulk_DryRun_NoMutation(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
	fx.seedFinding("f-2", "open", fx.now.Add(-72*time.Hour), nil)

	result, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-dry-1", true))
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk dry-run error = %v", err)
	}
	if result.ProposedCount != 2 {
		t.Fatalf("ProposedCount = %d, want 2", result.ProposedCount)
	}
	if result.AppliedCount != 0 {
		t.Fatalf("AppliedCount = %d, want 0", result.AppliedCount)
	}
	for _, finding := range fx.store.findings {
		if finding.Tombstoned {
			t.Fatalf("finding %s tombstoned after dry-run", finding.ID)
		}
	}
	if events := fx.tombstone.snapshot(); len(events) != 0 {
		t.Fatalf("dry-run wrote %d audit events, want 0", len(events))
	}
	if fx.store.updateStatusCallCount != 0 {
		t.Fatalf("dry-run made %d UpdateFindingStatus calls, want 0", fx.store.updateStatusCallCount)
	}
	run, err := fx.closeout.GetCloseoutRun(context.Background(), "run-dry-1")
	if err != nil {
		t.Fatalf("GetCloseoutRun error = %v", err)
	}
	if run.Status != "succeeded" {
		t.Fatalf("closeout_run status = %q, want succeeded", run.Status)
	}
	if !run.DryRun {
		t.Fatalf("closeout_run dry_run = false, want true")
	}
	if run.AppliedCount != 0 || run.ProposedCount != 2 {
		t.Fatalf("closeout_run counts = (%d proposed, %d applied), want (2,0)", run.ProposedCount, run.AppliedCount)
	}
}

func TestTombstoneFindingsBulk_Apply_PersistsAndEmits(t *testing.T) {
	fx := newCloseoutFixture(t)
	first := fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
	second := fx.seedFinding("f-2", "open", fx.now.Add(-72*time.Hour), nil)

	result, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-apply-1", false))
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk apply error = %v", err)
	}
	if result.ProposedCount != 2 || result.AppliedCount != 2 {
		t.Fatalf("ProposedCount=%d AppliedCount=%d, want 2/2", result.ProposedCount, result.AppliedCount)
	}
	for _, id := range []string{first.ID, second.ID} {
		stored := fx.store.findings[id]
		if !stored.Tombstoned {
			t.Fatalf("finding %s not tombstoned", id)
		}
		if stored.Status != findingStatusResolved {
			t.Fatalf("finding %s status = %q, want resolved", id, stored.Status)
		}
		if stored.PriorStatus != "open" {
			t.Fatalf("finding %s prior_status = %q, want open", id, stored.PriorStatus)
		}
		if stored.TombstonedBy != "operator@writer.com" {
			t.Fatalf("finding %s tombstoned_by = %q", id, stored.TombstonedBy)
		}
		if stored.TombstonedRunID != "run-apply-1" {
			t.Fatalf("finding %s tombstoned_run_id = %q", id, stored.TombstonedRunID)
		}
		if stored.TombstonedReason != "bulk closeout: pre-conversion backlog" {
			t.Fatalf("finding %s tombstoned_reason = %q", id, stored.TombstonedReason)
		}
		if stored.TombstonedAt.IsZero() {
			t.Fatalf("finding %s tombstoned_at is zero", id)
		}
		if stored.StatusUpdatedAt.IsZero() {
			t.Fatalf("finding %s status_updated_at is zero", id)
		}
	}
	events := fx.tombstone.snapshot()
	if len(events) != 2 {
		t.Fatalf("audit events = %d, want 2", len(events))
	}
	emitted := 0
	for _, evt := range fx.appendLog.events {
		if evt.GetKind() == "workflow.v1.finding.tombstoned" {
			emitted++
		}
	}
	if emitted != 2 {
		t.Fatalf("workflow tombstoned events emitted = %d, want 2", emitted)
	}
	run, _ := fx.closeout.GetCloseoutRun(context.Background(), "run-apply-1")
	if run.Status != "succeeded" {
		t.Fatalf("closeout_run.status = %q, want succeeded", run.Status)
	}
	if run.AppliedCount != 2 {
		t.Fatalf("closeout_run.applied_count = %d, want 2", run.AppliedCount)
	}
	if run.FinishedAt.IsZero() {
		t.Fatalf("closeout_run.finished_at is zero")
	}
}

func TestTombstoneFindingsBulk_PreservesManualState(t *testing.T) {
	fx := newCloseoutFixture(t)
	manualNote := ports.FindingNote{
		ID:        "note-1",
		Body:      "previously triaged",
		CreatedAt: fx.now.Add(-12 * time.Hour),
	}
	manualTicket := ports.FindingTicket{
		URL:        "https://jira.example/PROJ-42",
		Name:       "PROJ-42",
		ExternalID: "PROJ-42",
		LinkedAt:   fx.now.Add(-10 * time.Hour),
	}
	fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), func(f *ports.FindingRecord) {
		f.Assignee = "alice@writer.com"
		f.Notes = []ports.FindingNote{manualNote}
		f.Tickets = []ports.FindingTicket{manualTicket}
	})
	before := cloneFinding(fx.store.findings["f-1"])

	if _, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-manual-1", false)); err != nil {
		t.Fatalf("TombstoneFindingsBulk error = %v", err)
	}
	after := fx.store.findings["f-1"]
	if after.Assignee != before.Assignee {
		t.Fatalf("assignee changed: before=%q after=%q", before.Assignee, after.Assignee)
	}
	if !reflect.DeepEqual(before.Notes, after.Notes) {
		t.Fatalf("notes changed: before=%v after=%v", before.Notes, after.Notes)
	}
	if !reflect.DeepEqual(before.Tickets, after.Tickets) {
		t.Fatalf("tickets changed: before=%v after=%v", before.Tickets, after.Tickets)
	}
}

func TestTombstoneFindingsBulk_PreservesObservationTimestamps(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
	before := cloneFinding(fx.store.findings["f-1"])

	if _, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-obs-1", false)); err != nil {
		t.Fatalf("TombstoneFindingsBulk error = %v", err)
	}
	after := fx.store.findings["f-1"]
	if !after.FirstObservedAt.Equal(before.FirstObservedAt) {
		t.Fatalf("first_observed_at changed: before=%v after=%v", before.FirstObservedAt, after.FirstObservedAt)
	}
	if !after.LastObservedAt.Equal(before.LastObservedAt) {
		t.Fatalf("last_observed_at changed: before=%v after=%v", before.LastObservedAt, after.LastObservedAt)
	}
}

func TestTombstoneFindingsBulk_DefaultExcludesSuppressedResolved(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFinding("f-open", "open", fx.now.Add(-48*time.Hour), nil)
	fx.seedFinding("f-suppressed", "suppressed", fx.now.Add(-48*time.Hour), nil)
	fx.seedFinding("f-resolved", "resolved", fx.now.Add(-48*time.Hour), nil)

	result, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-default-1", true))
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk error = %v", err)
	}
	if result.ProposedCount != 1 {
		t.Fatalf("ProposedCount = %d, want 1", result.ProposedCount)
	}
	if id := strings.TrimSpace(result.Proposed[0].ID); id != "f-open" {
		t.Fatalf("Proposed[0].ID = %q, want f-open", id)
	}
}

func TestTombstoneFindingsBulk_RoutesThroughUpdateFindingStatusAndRisk(t *testing.T) {
	fx := newCloseoutFixture(t)
	for i := 0; i < 4; i++ {
		fx.seedFinding(fmt.Sprintf("f-%d", i), "open", fx.now.Add(-48*time.Hour), nil)
	}
	before := fx.store.upsertCount
	if _, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-route-1", false)); err != nil {
		t.Fatalf("TombstoneFindingsBulk error = %v", err)
	}
	if fx.store.updateStatusCallCount != 4 {
		t.Fatalf("UpdateFindingStatus call count = %d, want 4", fx.store.updateStatusCallCount)
	}
	for _, call := range fx.store.updateStatusCalls {
		if call.Tombstone == nil {
			t.Fatalf("UpdateFindingStatus called without Tombstone payload: %+v", call)
		}
	}
	if got := fx.store.upsertCount - before; got != 0 {
		t.Fatalf("UpsertFinding called %d times during closeout, want 0 (no raw-UPDATE bypasses)", got)
	}
}

func TestTombstoneFindingsBulk_CloseoutRunLifecycle(t *testing.T) {
	t.Run("succeeded", func(t *testing.T) {
		fx := newCloseoutFixture(t)
		fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
		if _, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-lc-1", false)); err != nil {
			t.Fatalf("TombstoneFindingsBulk error = %v", err)
		}
		run, _ := fx.closeout.GetCloseoutRun(context.Background(), "run-lc-1")
		if run.Status != "succeeded" {
			t.Fatalf("status = %q, want succeeded", run.Status)
		}
		if run.AppliedCount != 1 {
			t.Fatalf("applied_count = %d, want 1", run.AppliedCount)
		}
		if run.FinishedAt.IsZero() {
			t.Fatalf("finished_at is zero")
		}
	})
	t.Run("failed_on_batch_error", func(t *testing.T) {
		fx := newCloseoutFixture(t)
		fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
		// Force tombstone-event insert failure.
		fx.tombstone = &stubFindingTombstoneEventStore{}
		fx.service.tombstoneEventStore = &explodingTombstoneEventStore{err: errors.New("boom")}
		_, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-lc-2", false))
		if err == nil {
			t.Fatalf("TombstoneFindingsBulk should error on batch failure")
		}
		run, _ := fx.closeout.GetCloseoutRun(context.Background(), "run-lc-2")
		if run.Status != "failed" {
			t.Fatalf("status = %q, want failed", run.Status)
		}
		if run.ErrorMessage == "" {
			t.Fatalf("error_message is empty")
		}
		if run.FinishedAt.IsZero() {
			t.Fatalf("finished_at is zero")
		}
	})
}

type explodingTombstoneEventStore struct {
	err error
}

func (s *explodingTombstoneEventStore) InsertFindingTombstoneEvent(context.Context, ports.FindingTombstoneEvent) error {
	return s.err
}

func (s *explodingTombstoneEventStore) CountFindingTombstoneEventsByRun(context.Context, string) (int, error) {
	return 0, nil
}

func TestTombstoneFindingsBulk_LockReleasedOnAllExitPaths(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fx := newCloseoutFixture(t)
		fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
		if _, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-lock-1", false)); err != nil {
			t.Fatalf("error = %v", err)
		}
		run, _ := fx.closeout.GetCloseoutRun(context.Background(), "run-lock-1")
		if run.Status == "running" {
			t.Fatalf("status remained running after success")
		}
		if run.FinishedAt.IsZero() {
			t.Fatalf("finished_at is zero")
		}
	})
	t.Run("batch_error", func(t *testing.T) {
		fx := newCloseoutFixture(t)
		fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
		fx.service.tombstoneEventStore = &explodingTombstoneEventStore{err: errors.New("kaboom")}
		_, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-lock-2", false))
		if err == nil {
			t.Fatalf("expected error")
		}
		run, _ := fx.closeout.GetCloseoutRun(context.Background(), "run-lock-2")
		if run.Status == "running" {
			t.Fatalf("status remained running after batch error")
		}
		if run.FinishedAt.IsZero() {
			t.Fatalf("finished_at is zero after batch error")
		}
	})
	t.Run("ctx_cancel", func(t *testing.T) {
		fx := newCloseoutFixture(t)
		fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
		fx.seedFinding("f-2", "open", fx.now.Add(-72*time.Hour), nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := fx.service.TombstoneFindingsBulk(ctx, fx.request("run-lock-3", false))
		if err == nil {
			t.Fatalf("expected ctx.Err()")
		}
		run, _ := fx.closeout.GetCloseoutRun(context.Background(), "run-lock-3")
		if run.Status == "running" {
			t.Fatalf("status remained running after ctx cancel")
		}
		if run.FinishedAt.IsZero() {
			t.Fatalf("finished_at is zero after ctx cancel")
		}
	})
	t.Run("panic", func(t *testing.T) {
		fx := newCloseoutFixture(t)
		fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
		fx.service.tombstoneEventStore = &panickyTombstoneEventStore{}
		func() {
			defer func() { _ = recover() }()
			_, _ = fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-lock-4", false))
		}()
		run, _ := fx.closeout.GetCloseoutRun(context.Background(), "run-lock-4")
		if run.Status == "running" {
			t.Fatalf("status remained running after panic recovery, got %q", run.Status)
		}
		if run.FinishedAt.IsZero() {
			t.Fatalf("finished_at is zero after panic recovery")
		}
	})
}

type panickyTombstoneEventStore struct{}

func (s *panickyTombstoneEventStore) InsertFindingTombstoneEvent(context.Context, ports.FindingTombstoneEvent) error {
	panic("inject panic")
}

func (s *panickyTombstoneEventStore) CountFindingTombstoneEventsByRun(context.Context, string) (int, error) {
	return 0, nil
}

func TestTombstoneFindingsBulk_SelectorJSONIsResolvedSnapshot(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
	req := fx.request("run-sel-1", false)
	req.Selector.OlderThan = 24 * time.Hour
	if _, err := fx.service.TombstoneFindingsBulk(context.Background(), req); err != nil {
		t.Fatalf("error = %v", err)
	}
	run, _ := fx.closeout.GetCloseoutRun(context.Background(), "run-sel-1")
	var got CloseoutSelector
	if err := json.Unmarshal(run.SelectorJSON, &got); err != nil {
		t.Fatalf("unmarshal selector_json: %v", err)
	}
	want := CloseoutSelector{
		TenantID:  fx.tenantID,
		RuleIDs:   []string{fx.ruleID},
		OlderThan: 24 * time.Hour,
		Statuses:  []string{findingStatusOpen},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selector_json = %+v, want %+v", got, want)
	}
}

func TestTombstoneFindingsBulk_FailsFastWhenAnotherRunning(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
	if err := fx.closeout.InsertCloseoutRun(context.Background(), ports.CloseoutRunInsert{
		RunID:        "run-blocking",
		Actor:        "operator",
		SelectorJSON: []byte(`{}`),
		StartedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed blocking run: %v", err)
	}
	beforeTombstoned := tombstonedCount(fx.store)
	_, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-fail-fast-1", false))
	if err == nil {
		t.Fatalf("expected fail-fast error, got nil")
	}
	if !errors.Is(err, ErrCloseoutAnotherRunning) {
		t.Fatalf("err = %v, want ErrCloseoutAnotherRunning", err)
	}
	if got := tombstonedCount(fx.store); got != beforeTombstoned {
		t.Fatalf("tombstoned count changed: before=%d after=%d", beforeTombstoned, got)
	}
}

func TestTombstoneFindingsBulk_Idempotent_SameRunID(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
	first, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-idem-1", false))
	if err != nil {
		t.Fatalf("first apply error = %v", err)
	}
	if first.AppliedCount != 1 {
		t.Fatalf("first applied_count = %d, want 1", first.AppliedCount)
	}
	beforeAuditCount, _ := fx.tombstone.CountFindingTombstoneEventsByRun(context.Background(), "run-idem-1")
	second, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-idem-1", false))
	if err != nil {
		t.Fatalf("second apply error = %v", err)
	}
	if second.AppliedCount != 0 {
		t.Fatalf("second applied_count = %d, want 0", second.AppliedCount)
	}
	afterAuditCount, _ := fx.tombstone.CountFindingTombstoneEventsByRun(context.Background(), "run-idem-1")
	if afterAuditCount != beforeAuditCount {
		t.Fatalf("audit count changed: before=%d after=%d", beforeAuditCount, afterAuditCount)
	}
}

func TestTombstoneFindingsBulk_BatchesAtMaxBatchSize(t *testing.T) {
	fx := newCloseoutFixture(t)
	for i := 0; i < 25; i++ {
		fx.seedFinding(fmt.Sprintf("f-%02d", i), "open", fx.now.Add(-48*time.Hour-time.Duration(i)*time.Second), nil)
	}
	req := fx.request("run-batch-1", false)
	req.MaxBatchSize = 10
	result, err := fx.service.TombstoneFindingsBulk(context.Background(), req)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if result.AppliedCount != 25 {
		t.Fatalf("AppliedCount = %d, want 25", result.AppliedCount)
	}
	want := []int{10, 10, 5}
	if !reflect.DeepEqual(result.BatchSizes, want) {
		t.Fatalf("BatchSizes = %v, want %v", result.BatchSizes, want)
	}
}

func TestTombstoneFindingsBulk_OlderThanFilter(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFinding("f-1d", "open", time.Now().UTC().Add(-1*24*time.Hour), nil)
	fx.seedFinding("f-8d", "open", time.Now().UTC().Add(-8*24*time.Hour), nil)
	fx.seedFinding("f-30d", "open", time.Now().UTC().Add(-30*24*time.Hour), nil)
	req := fx.request("run-older-1", true)
	req.Selector.OlderThan = 7 * 24 * time.Hour
	result, err := fx.service.TombstoneFindingsBulk(context.Background(), req)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	ids := sortedProposedIDs(result.Proposed)
	want := []string{"f-30d", "f-8d"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("proposed ids = %v, want %v", ids, want)
	}
}

func TestTombstoneFindingsBulk_AuditRowFieldFidelity(t *testing.T) {
	fx := newCloseoutFixture(t)
	primary := "urn:cerebro:writer:github_repo:writer/cerebro"
	fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), func(f *ports.FindingRecord) {
		f.ResourceURNs = []string{primary}
	})
	if _, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-audit-1", false)); err != nil {
		t.Fatalf("error = %v", err)
	}
	events := fx.tombstone.snapshot()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	evt := events[0]
	if evt.FindingID != "f-1" {
		t.Fatalf("finding_id = %q, want f-1", evt.FindingID)
	}
	if evt.TenantID != fx.tenantID {
		t.Fatalf("tenant_id = %q, want %q", evt.TenantID, fx.tenantID)
	}
	if evt.RuleID != fx.ruleID {
		t.Fatalf("rule_id = %q, want %q", evt.RuleID, fx.ruleID)
	}
	if evt.AnchorURI != primary {
		t.Fatalf("anchor_uri = %q, want %q", evt.AnchorURI, primary)
	}
	if evt.PriorStatus != "open" {
		t.Fatalf("prior_status = %q, want open", evt.PriorStatus)
	}
	if evt.Reason != "bulk closeout: pre-conversion backlog" {
		t.Fatalf("reason = %q", evt.Reason)
	}
	if evt.Actor != "operator@writer.com" {
		t.Fatalf("actor = %q", evt.Actor)
	}
	if evt.RunID != "run-audit-1" {
		t.Fatalf("run_id = %q", evt.RunID)
	}
	if evt.TombstonedAt.IsZero() {
		t.Fatalf("tombstoned_at is zero")
	}
}

func TestResolvers_LeaveTombstonedRowsUntouched(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
	if _, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-resolvers-1", false)); err != nil {
		t.Fatalf("seed tombstone error = %v", err)
	}
	before := cloneFinding(fx.store.findings["f-1"])
	if !before.Tombstoned {
		t.Fatalf("precondition: row must be tombstoned")
	}
	statusCallsBefore := fx.store.updateStatusCallCount

	// Force the stub to surface the tombstoned (now status=resolved) row when the
	// resolver queries open findings to prove the resolver still skips it even if
	// the listing returns it.
	fx.store.findings["f-1"].Status = "open"

	if err := fx.service.resolveStaleOpenFindings(context.Background(), fx.tenantID, fx.runtimeID, fx.ruleID,
		map[string]struct{}{"event-f-1": {}},
		map[string]struct{}{},
	); err != nil {
		t.Fatalf("resolveStaleOpenFindings error = %v", err)
	}
	if err := fx.service.resolveRetiredOpenFindings(context.Background(), fx.tenantID, fx.runtimeID, fx.ruleID,
		map[string]struct{}{},
	); err != nil {
		t.Fatalf("resolveRetiredOpenFindings error = %v", err)
	}

	after := fx.store.findings["f-1"]
	if fx.store.updateStatusCallCount != statusCallsBefore {
		t.Fatalf("resolvers performed %d additional UpdateFindingStatus calls (raw bypasses)",
			fx.store.updateStatusCallCount-statusCallsBefore)
	}
	if after.Tombstoned != before.Tombstoned {
		t.Fatalf("tombstoned changed: before=%v after=%v", before.Tombstoned, after.Tombstoned)
	}
	if !after.TombstonedAt.Equal(before.TombstonedAt) {
		t.Fatalf("tombstoned_at changed: before=%v after=%v", before.TombstonedAt, after.TombstonedAt)
	}
	if after.TombstonedBy != before.TombstonedBy {
		t.Fatalf("tombstoned_by changed: before=%q after=%q", before.TombstonedBy, after.TombstonedBy)
	}
	if after.TombstonedReason != before.TombstonedReason {
		t.Fatalf("tombstoned_reason changed: before=%q after=%q", before.TombstonedReason, after.TombstonedReason)
	}
	if after.TombstonedRunID != before.TombstonedRunID {
		t.Fatalf("tombstoned_run_id changed: before=%q after=%q", before.TombstonedRunID, after.TombstonedRunID)
	}
	if after.PriorStatus != before.PriorStatus {
		t.Fatalf("prior_status changed: before=%q after=%q", before.PriorStatus, after.PriorStatus)
	}
	if after.TombstoneGeneration != before.TombstoneGeneration {
		t.Fatalf("tombstone_generation changed: before=%d after=%d", before.TombstoneGeneration, after.TombstoneGeneration)
	}
}

func TestTombstoneFindingsBulk_SourceSelectorExpandsToRuleIDs(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFindingWithRule("f-gh-1", "github-critical-resource-deleted", "open", fx.now.Add(-48*time.Hour), nil)
	fx.seedFindingWithRule("f-gh-2", "github-webhook-modified", "open", fx.now.Add(-72*time.Hour), nil)
	fx.seedFindingWithRule("f-okta-1", "identity-okta-deprovisioned-active-in-github", "open", fx.now.Add(-48*time.Hour), nil)

	req := fx.request("run-src-1", false)
	req.Selector.RuleIDs = nil
	req.Selector.Sources = []string{"github"}

	result, err := fx.service.TombstoneFindingsBulk(context.Background(), req)
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk source-only error = %v", err)
	}
	if result.AppliedCount != 2 {
		t.Fatalf("AppliedCount = %d, want 2", result.AppliedCount)
	}
	for _, id := range []string{"f-gh-1", "f-gh-2"} {
		if !fx.store.findings[id].Tombstoned {
			t.Fatalf("finding %s not tombstoned", id)
		}
	}
	if fx.store.findings["f-okta-1"].Tombstoned {
		t.Fatalf("finding f-okta-1 tombstoned despite different source")
	}
}

func TestTombstoneFindingsBulk_SourceAndRuleIDsUnion(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFindingWithRule("f-gh-1", "github-critical-resource-deleted", "open", fx.now.Add(-48*time.Hour), nil)
	fx.seedFindingWithRule("f-id-1", "identity-mfa-factor-reset-or-disabled", "open", fx.now.Add(-48*time.Hour), nil)
	fx.seedFindingWithRule("f-okta-1", "identity-okta-deprovisioned-active-in-github", "open", fx.now.Add(-48*time.Hour), nil)

	req := fx.request("run-union-1", false)
	req.Selector.RuleIDs = []string{"identity-mfa-factor-reset-or-disabled"}
	req.Selector.Sources = []string{"github"}

	result, err := fx.service.TombstoneFindingsBulk(context.Background(), req)
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk union error = %v", err)
	}
	if result.AppliedCount != 2 {
		t.Fatalf("AppliedCount = %d, want 2", result.AppliedCount)
	}
	for _, id := range []string{"f-gh-1", "f-id-1"} {
		if !fx.store.findings[id].Tombstoned {
			t.Fatalf("finding %s not tombstoned", id)
		}
	}
	if fx.store.findings["f-okta-1"].Tombstoned {
		t.Fatalf("finding f-okta-1 tombstoned, expected untouched")
	}
}

func TestTombstoneFindingsBulk_RejectsEmptySelector(t *testing.T) {
	fx := newCloseoutFixture(t)
	req := fx.request("run-empty-1", false)
	req.Selector.RuleIDs = nil
	req.Selector.Sources = nil

	_, err := fx.service.TombstoneFindingsBulk(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, ErrCloseoutInvalidRequest) {
		t.Fatalf("err = %v, want ErrCloseoutInvalidRequest", err)
	}
}

func tombstonedCount(store *stubFindingStore) int {
	count := 0
	for _, finding := range store.findings {
		if finding.Tombstoned {
			count++
		}
	}
	return count
}

func sortedProposedIDs(records []*ports.FindingRecord) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, strings.TrimSpace(record.ID))
	}
	sort.Strings(ids)
	return ids
}
