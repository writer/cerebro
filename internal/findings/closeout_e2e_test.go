package findings_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/statestore/postgres"
	"github.com/writer/cerebro/internal/workflowevents"
	"github.com/writer/cerebro/internal/workflowprojection"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestService_TombstonedFindingEmitMintsFreshGraphEdge exercises the
// tombstone-then-emit lifecycle end-to-end against the real Postgres upsert
// path so the fresh-row mint (id = `<base>#g<N+1>` and tombstone_generation)
// is derived by the production internal/statestore/postgres UpsertFinding via
// the tombstoned fingerprint history instead of being pre-constructed by the
// test. F1 is upserted, tombstoned via Service.TombstoneFindingsBulk (which
// removes has_finding(A → F1) via the projector), and a subsequent emit on the
// same (rule_id, anchor_uri, fingerprint) re-runs through real UpsertFinding,
// which is what is expected to mint F2 with tombstoned=FALSE and the
// incremented generation. The fresh F2 is then anchored back into the graph
// so the test confirms has_finding(A → F2) is reattached.
func TestService_TombstonedFindingEmitMintsFreshGraphEdge(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run the end-to-end tombstone-then-emit integration test")
	}

	ctx := context.Background()
	store, err := postgres.Open(config.StateStoreConfig{
		Driver:      config.StateStoreDriverPostgres,
		PostgresDSN: dsn,
	})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	rawDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	t.Cleanup(func() { _ = rawDB.Close() })

	nonce := time.Now().UTC().UnixNano()
	tenantID := fmt.Sprintf("tenant-e2e-%d", nonce)
	runtimeID := fmt.Sprintf("runtime-e2e-%d", nonce)
	ruleID := "rule-critical-resource-deleted"
	baseID := fmt.Sprintf("f-stable-%d", nonce)
	fingerprint := fmt.Sprintf("fp-stable-%d", nonce)
	anchor := fmt.Sprintf("urn:cerebro:%s:github_repo:writer/cerebro-%d", tenantID, nonce)

	t.Cleanup(func() {
		bg := context.Background()
		_, _ = rawDB.ExecContext(bg, `DELETE FROM finding_tombstone_events WHERE tenant_id = $1`, tenantID)
		_, _ = rawDB.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tenantID)
	})

	graph := newE2EGraphFake()
	appendLog := &recordingAppendLog{}
	closeoutStore := newStubCloseoutStore()
	tombstoneEventStore := newStubFindingTombstoneEventStore()
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {Id: runtimeID, SourceId: "source-e2e", TenantId: tenantID},
		},
	}

	service := findings.New(runtimeStore, &stubReplayer{}, store, store, store, store).
		WithAppendLog(appendLog).
		WithGraphStore(graph).
		WithCloseoutStore(closeoutStore).
		WithFindingTombstoneEventStore(tombstoneEventStore)

	now := time.Now().UTC().Truncate(time.Microsecond)
	firstObserved := now.Add(-48 * time.Hour)
	firstEmit := &ports.FindingRecord{
		ID:              baseID,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       runtimeID,
		RuleID:          ruleID,
		Title:           "T " + baseID,
		Severity:        "MEDIUM",
		Status:          "open",
		Summary:         "S " + baseID,
		ResourceURNs:    []string{anchor},
		EventIDs:        []string{"event-initial-emit"},
		FirstObservedAt: firstObserved,
		LastObservedAt:  firstObserved,
	}
	storedF1, err := store.UpsertFinding(ctx, firstEmit)
	if err != nil {
		t.Fatalf("UpsertFinding F1: %v", err)
	}
	if storedF1.ID != baseID {
		t.Fatalf("F1.ID = %q, want %q", storedF1.ID, baseID)
	}

	if err := projectFindingAnchorForTest(ctx, appendLog, graph, storedF1); err != nil {
		t.Fatalf("project F1 anchor: %v", err)
	}

	firstAnchorEdgeKey := anchorEdgeKey(anchor, tenantID, storedF1.ID)
	if _, ok := graph.links[firstAnchorEdgeKey]; !ok {
		t.Fatalf("pre-condition: missing has_finding(A → F1) edge %q (links=%v)", firstAnchorEdgeKey, graph.links)
	}

	result, err := service.TombstoneFindingsBulk(ctx, findings.CloseoutRequest{
		Selector: findings.CloseoutSelector{
			TenantID: tenantID,
			RuleIDs:  []string{ruleID},
		},
		Reason: "bulk closeout: pre-conversion backlog",
		Actor:  "operator@writer.com",
		RunID:  fmt.Sprintf("run-e2e-%d", nonce),
		DryRun: false,
	})
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk: %v", err)
	}
	if result.AppliedCount != 1 {
		t.Fatalf("AppliedCount = %d, want 1", result.AppliedCount)
	}

	if !tombstonedFromDB(t, ctx, rawDB, baseID) {
		t.Fatalf("findings.tombstoned = false for F1 %q, want true after bulk tombstone", baseID)
	}
	if _, ok := graph.links[firstAnchorEdgeKey]; ok {
		t.Fatalf("expected has_finding(A → F1) edge %q to be removed after tombstone", firstAnchorEdgeKey)
	}

	tombstoneEvents := 0
	for _, evt := range appendLog.events {
		if evt.GetKind() == workflowevents.EventKindFindingTombstoned {
			tombstoneEvents++
		}
	}
	if tombstoneEvents != 1 {
		t.Fatalf("FindingTombstoned events emitted for F1 = %d, want 1", tombstoneEvents)
	}

	firstGen := generationFromDB(t, ctx, rawDB, baseID)

	freshEmit := &ports.FindingRecord{
		ID:              baseID,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       runtimeID,
		RuleID:          ruleID,
		Title:           "T " + baseID,
		Severity:        "MEDIUM",
		Status:          "open",
		Summary:         "S " + baseID,
		ResourceURNs:    []string{anchor},
		EventIDs:        []string{"event-fresh-emit"},
		FirstObservedAt: now.Add(-time.Minute),
		LastObservedAt:  now,
	}
	storedF2, err := store.UpsertFinding(ctx, freshEmit)
	if err != nil {
		t.Fatalf("UpsertFinding F2: %v", err)
	}

	wantSecondID := fmt.Sprintf("%s#g%d", baseID, firstGen+1)
	if storedF2.ID != wantSecondID {
		t.Fatalf("F2.ID = %q, want %q (derived by UpsertFinding from tombstoned fingerprint history)", storedF2.ID, wantSecondID)
	}
	if storedF2.ID == storedF1.ID {
		t.Fatalf("F2.ID %q must differ from tombstoned F1.ID %q", storedF2.ID, storedF1.ID)
	}

	secondGen := generationFromDB(t, ctx, rawDB, storedF2.ID)
	if secondGen != firstGen+1 {
		t.Fatalf("F2.tombstone_generation = %d, want F1.tombstone_generation+1 = %d", secondGen, firstGen+1)
	}

	secondTombstoned := tombstonedFromDB(t, ctx, rawDB, storedF2.ID)
	if secondTombstoned {
		t.Fatalf("F2.tombstoned = true, want false")
	}

	if err := projectFindingAnchorForTest(ctx, appendLog, graph, storedF2); err != nil {
		t.Fatalf("project F2 anchor: %v", err)
	}

	recordedForF2 := 0
	for _, evt := range appendLog.events {
		if evt.GetKind() != workflowevents.EventKindFindingRecorded {
			continue
		}
		payload, decodeErr := workflowevents.DecodeFindingRecorded(evt)
		if decodeErr != nil {
			t.Fatalf("decode FindingRecorded: %v", decodeErr)
		}
		if payload.Finding.FindingID == storedF2.ID {
			recordedForF2++
		}
	}
	if recordedForF2 != 1 {
		t.Fatalf("FindingRecorded events for F2 = %d, want 1", recordedForF2)
	}

	freshAnchorEdgeKey := anchorEdgeKey(anchor, tenantID, storedF2.ID)
	if freshAnchorEdgeKey == firstAnchorEdgeKey {
		t.Fatalf("F2 edge key %q must differ from F1 edge key", freshAnchorEdgeKey)
	}
	if _, ok := graph.links[freshAnchorEdgeKey]; !ok {
		t.Fatalf("expected has_finding(A → F2) edge %q after fresh emit (links=%v)", freshAnchorEdgeKey, graph.links)
	}
}

func TestService_TTLEvidenceEvaluateUsesPostgresTenantScopeAndReopens(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run the postgres-backed TTL evaluate integration test")
	}

	ctx := context.Background()
	store, err := postgres.Open(config.StateStoreConfig{
		Driver:      config.StateStoreDriverPostgres,
		PostgresDSN: dsn,
	})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	rawDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	t.Cleanup(func() { _ = rawDB.Close() })

	nonce := time.Now().UTC().UnixNano()
	tenantID := fmt.Sprintf("tenant-ttl-e2e-%d", nonce)
	runtimeID := fmt.Sprintf("runtime-ttl-e2e-%d", nonce)
	evidenceID := fmt.Sprintf("evidence-ttl-e2e-%d", nonce)
	ruleID := "runtime-active-threat-evidence"
	openedAt := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	staleAt := openedAt.Add(25 * time.Hour)
	reemitAt := staleAt.Add(time.Hour)

	t.Cleanup(func() {
		bg := context.Background()
		_, _ = rawDB.ExecContext(bg, `DELETE FROM finding_evidence WHERE runtime_id = $1`, runtimeID)
		_, _ = rawDB.ExecContext(bg, `DELETE FROM finding_evaluation_runs WHERE runtime_id = $1`, runtimeID)
		_, _ = rawDB.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tenantID)
	})

	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {Id: runtimeID, SourceId: "runtime", TenantId: tenantID},
		},
	}
	replayer := &stubReplayer{events: []*cerebrov1.EventEnvelope{
		runtimeThreatE2EEvent("runtime-threat-open", tenantID, evidenceID, openedAt),
	}}
	service := findings.NewWithRegistry(runtimeStore, replayer, store, store, store, store, findings.Builtin()).
		WithTTLClock(e2eTTLClock{now: openedAt})

	openResult, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(open): %v", err)
	}
	if openResult == nil || len(openResult.Evaluations) != 1 {
		t.Fatalf("open result evaluations = %#v, want one", openResult)
	}
	if got := len(openResult.Evaluations[0].Findings); got != 1 {
		t.Fatalf("open result findings = %d, want 1", got)
	}
	opened := openResult.Evaluations[0].Findings[0]
	if got := strings.TrimSpace(opened.Status); got != "open" {
		t.Fatalf("opened status = %q, want open", got)
	}
	if got := strings.TrimSpace(opened.TenantID); got != tenantID {
		t.Fatalf("opened tenant_id = %q, want %q", got, tenantID)
	}

	replayer.events = nil
	service.WithTTLClock(e2eTTLClock{now: staleAt})
	if _, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	}); err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(ttl resolve): %v", err)
	}
	resolved, err := store.GetFinding(ctx, opened.ID)
	if err != nil {
		t.Fatalf("GetFinding(%q) after TTL resolve: %v", opened.ID, err)
	}
	if got := strings.TrimSpace(resolved.Status); got != "resolved" {
		t.Fatalf("TTL-resolved status = %q, want resolved", got)
	}
	if got := strings.TrimSpace(resolved.StatusReason); got != "ttl_expired:24h" {
		t.Fatalf("TTL-resolved status_reason = %q, want ttl_expired:24h", got)
	}
	if resolved.Tombstoned {
		t.Fatalf("TTL-resolved finding tombstoned = true, want false")
	}

	replayer.events = []*cerebrov1.EventEnvelope{
		runtimeThreatE2EEvent("runtime-threat-reemit", tenantID, evidenceID, reemitAt),
	}
	service.WithTTLClock(e2eTTLClock{now: reemitAt})
	reopenResult, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(reemit): %v", err)
	}
	if reopenResult == nil || len(reopenResult.Evaluations) != 1 || len(reopenResult.Evaluations[0].Findings) != 1 {
		t.Fatalf("reemit result = %#v, want one reopened finding", reopenResult)
	}
	reopenedFromResult := reopenResult.Evaluations[0].Findings[0]
	if got := strings.TrimSpace(reopenedFromResult.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("reemit finding id = %q, want original id %q from real upsert reopen path", got, opened.ID)
	}
	reopened, err := store.GetFinding(ctx, opened.ID)
	if err != nil {
		t.Fatalf("GetFinding(%q) after reemit: %v", opened.ID, err)
	}
	if got := strings.TrimSpace(reopened.Status); got != "open" {
		t.Fatalf("reopened status = %q, want open", got)
	}
	if got := strings.TrimSpace(reopened.StatusReason); got != "" {
		t.Fatalf("reopened status_reason = %q, want empty", got)
	}
	if reopened.Tombstoned {
		t.Fatalf("reopened finding tombstoned = true, want false")
	}
	if strings.Contains(reopened.ID, "#g") {
		t.Fatalf("reopened finding id = %q, want original non-generation row for non-tombstoned TTL reopen", reopened.ID)
	}

	var activeRows int
	if err := rawDB.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND rule_id = $2 AND fingerprint = $3 AND tombstoned = FALSE`, tenantID, ruleID, opened.Fingerprint).Scan(&activeRows); err != nil {
		t.Fatalf("count active TTL rows: %v", err)
	}
	if activeRows != 1 {
		t.Fatalf("active rows for reopened TTL fingerprint = %d, want 1", activeRows)
	}
}

func anchorEdgeKey(anchor, tenantID, findingID string) string {
	return anchor + "|has_finding|" + fmt.Sprintf("urn:cerebro:%s:finding:%s", tenantID, findingID)
}

func generationFromDB(t *testing.T, ctx context.Context, db *sql.DB, findingID string) int {
	t.Helper()
	var gen int
	if err := db.QueryRowContext(ctx, `SELECT tombstone_generation FROM findings WHERE id = $1`, findingID).Scan(&gen); err != nil {
		t.Fatalf("read tombstone_generation for %q: %v", findingID, err)
	}
	return gen
}

func tombstonedFromDB(t *testing.T, ctx context.Context, db *sql.DB, findingID string) bool {
	t.Helper()
	var tombstoned bool
	if err := db.QueryRowContext(ctx, `SELECT tombstoned FROM findings WHERE id = $1`, findingID).Scan(&tombstoned); err != nil {
		t.Fatalf("read tombstoned for %q: %v", findingID, err)
	}
	return tombstoned
}

func projectFindingAnchorForTest(ctx context.Context, appendLog *recordingAppendLog, graph *e2eGraphFake, finding *ports.FindingRecord) error {
	if finding == nil {
		return errors.New("finding is required")
	}
	recordedAt := finding.LastObservedAt.UTC()
	if recordedAt.IsZero() {
		recordedAt = finding.FirstObservedAt.UTC()
	}
	if recordedAt.IsZero() {
		recordedAt = time.Now().UTC()
	}
	resourceURNs := append([]string(nil), finding.ResourceURNs...)
	primary := ""
	if len(resourceURNs) > 0 {
		primary = resourceURNs[0]
	}
	snapshot := workflowevents.FindingSnapshot{
		TenantID:           strings.TrimSpace(finding.TenantID),
		SourceSystem:       strings.TrimSpace(finding.RuntimeID),
		FindingID:          strings.TrimSpace(finding.ID),
		Fingerprint:        strings.TrimSpace(finding.Fingerprint),
		Title:              strings.TrimSpace(finding.Title),
		Summary:            strings.TrimSpace(finding.Summary),
		RuleID:             strings.TrimSpace(finding.RuleID),
		Severity:           strings.TrimSpace(finding.Severity),
		Status:             strings.TrimSpace(finding.Status),
		RuntimeID:          strings.TrimSpace(finding.RuntimeID),
		PrimaryResourceURN: primary,
		ResourceURNs:       resourceURNs,
		EventIDs:           append([]string(nil), finding.EventIDs...),
		FirstObservedAt:    timestampOrEmpty(finding.FirstObservedAt),
		LastObservedAt:     timestampOrEmpty(finding.LastObservedAt),
		ResourceCount:      len(resourceURNs),
		EventCount:         len(finding.EventIDs),
	}
	event, err := workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding:    snapshot,
		RecordedAt: recordedAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	if err := appendLog.Append(ctx, event); err != nil {
		return err
	}
	if _, err := workflowprojection.New(graph).Project(ctx, event); err != nil {
		return err
	}
	return nil
}

func timestampOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

type e2eTTLClock struct {
	now time.Time
}

func (c e2eTTLClock) Now() time.Time { return c.now }

func runtimeThreatE2EEvent(id string, tenantID string, evidenceID string, observedAt time.Time) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   tenantID,
		SourceId:   "runtime",
		Kind:       "runtime.evidence",
		OccurredAt: timestamppb.New(observedAt),
		Attributes: map[string]string{
			"confidence":    "0.95",
			"evidence_id":   evidenceID,
			"evidence_type": "credential_use",
			"resource_urn":  fmt.Sprintf("urn:cerebro:%s:kubernetes_workload:prod-cluster:payments:workload-ttl-e2e", tenantID),
			"verdict":       "confirmed",
		},
	}
}

type e2eGraphFake struct {
	mu       sync.Mutex
	entities map[string]*ports.ProjectedEntity
	links    map[string]*ports.ProjectedLink
}

func newE2EGraphFake() *e2eGraphFake {
	return &e2eGraphFake{
		entities: map[string]*ports.ProjectedEntity{},
		links:    map[string]*ports.ProjectedLink{},
	}
}

func (g *e2eGraphFake) Ping(context.Context) error { return nil }

func (g *e2eGraphFake) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if entity == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	attributes := make(map[string]string, len(entity.Attributes))
	for k, v := range entity.Attributes {
		attributes[k] = v
	}
	g.entities[entity.URN] = &ports.ProjectedEntity{
		URN:        entity.URN,
		TenantID:   entity.TenantID,
		SourceID:   entity.SourceID,
		EntityType: entity.EntityType,
		Label:      entity.Label,
		Attributes: attributes,
	}
	return nil
}

func (g *e2eGraphFake) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	attributes := make(map[string]string, len(link.Attributes))
	for k, v := range link.Attributes {
		attributes[k] = v
	}
	g.links[link.FromURN+"|"+link.Relation+"|"+link.ToURN] = &ports.ProjectedLink{
		TenantID:   link.TenantID,
		SourceID:   link.SourceID,
		FromURN:    link.FromURN,
		ToURN:      link.ToURN,
		Relation:   link.Relation,
		Attributes: attributes,
	}
	return nil
}

func (g *e2eGraphFake) DeleteProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.links, link.FromURN+"|"+link.Relation+"|"+link.ToURN)
	return nil
}

func (g *e2eGraphFake) DeleteProjectedEntity(_ context.Context, urn string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.entities, urn)
	for key, link := range g.links {
		if link.FromURN == urn || link.ToURN == urn {
			delete(g.links, key)
		}
	}
	return nil
}

type recordingAppendLog struct {
	mu     sync.Mutex
	events []*cerebrov1.EventEnvelope
}

func (s *recordingAppendLog) Ping(context.Context) error { return nil }

func (s *recordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

type stubRuntimeStore struct {
	runtimes map[string]*cerebrov1.SourceRuntime
}

func (s *stubRuntimeStore) Ping(context.Context) error { return nil }

func (s *stubRuntimeStore) PutSourceRuntime(context.Context, *cerebrov1.SourceRuntime) error {
	return nil
}

func (s *stubRuntimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	runtime, ok := s.runtimes[id]
	if !ok {
		return nil, ports.ErrSourceRuntimeNotFound
	}
	return runtime, nil
}

type stubReplayer struct {
	events []*cerebrov1.EventEnvelope
}

func (s *stubReplayer) Replay(context.Context, ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	if s == nil || len(s.events) == 0 {
		return nil, nil
	}
	return append([]*cerebrov1.EventEnvelope(nil), s.events...), nil
}

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

func (s *stubCloseoutStore) BreakStaleRunningCloseoutRuns(_ context.Context, cutoff time.Time, errMessage string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cutoff.IsZero() {
		return 0, nil
	}
	broken := 0
	for _, existing := range s.runs {
		if existing.Status != "running" {
			continue
		}
		if !existing.StartedAt.Before(cutoff) {
			continue
		}
		existing.Status = "failed"
		existing.FinishedAt = time.Now().UTC()
		if strings.TrimSpace(errMessage) != "" {
			existing.ErrorMessage = errMessage
		}
		broken++
	}
	return broken, nil
}

func (s *stubCloseoutStore) UpdateCloseoutRunSummary(_ context.Context, runID, summaryKey string, summaryErr error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.runs[runID]
	if !ok {
		return fmt.Errorf("closeout_run %q not found", runID)
	}
	if summaryErr != nil {
		existing.Status = "failed"
		existing.FinishedAt = time.Now().UTC()
		existing.ErrorMessage = summaryErr.Error()
		return nil
	}
	if summaryKey != "" {
		existing.S3SummaryKey = summaryKey
	}
	return nil
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
