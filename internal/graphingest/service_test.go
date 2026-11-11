package graphingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/projectionmeta"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/telemetry"
)

type stubRunStore struct {
	runs    []graphstore.IngestRun
	putRuns []graphstore.IngestRun
	putFunc func(context.Context, graphstore.IngestRun) error
}

func (s *stubRunStore) Ping(context.Context) error { return nil }

func (s *stubRunStore) PutIngestRun(ctx context.Context, run graphstore.IngestRun) error {
	s.putRuns = append(s.putRuns, run)
	if s.putFunc != nil {
		return s.putFunc(ctx, run)
	}
	return nil
}

func (s *stubRunStore) GetIngestRun(context.Context, string) (graphstore.IngestRun, bool, error) {
	return graphstore.IngestRun{}, false, nil
}

func (s *stubRunStore) ListIngestRuns(_ context.Context, filter graphstore.IngestRunFilter) ([]graphstore.IngestRun, error) {
	runs := []graphstore.IngestRun{}
	for _, run := range s.runs {
		if filter.RuntimeID != "" && run.RuntimeID != filter.RuntimeID {
			continue
		}
		if len(filter.RuntimeIDs) != 0 && !graphIngestStringInSlice(filter.RuntimeIDs, run.RuntimeID) {
			continue
		}
		if filter.Status != "" && run.Status != filter.Status {
			continue
		}
		runs = append(runs, run)
	}
	if filter.LatestByRuntime {
		runs = latestRunsByRuntime(runs)
	}
	if filter.Limit != 0 && len(runs) > filter.Limit {
		runs = runs[:filter.Limit]
	}
	return runs, nil
}

func graphIngestStringInSlice(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

type recordProjectorFunc func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)

func (f recordProjectorFunc) Project(_ context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	entities, links, err := f(event)
	return ports.ProjectionResult{
		EntitiesProjected: boundedUint32(len(entities)),
		LinksProjected:    boundedUint32(len(links)),
	}, err
}

func (f recordProjectorFunc) ProjectRecords(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return f(event)
}

type contextRecordProjector struct {
	recordProjectorFunc
	projectContext func(context.Context, *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)
}

func (p contextRecordProjector) ProjectRecordsContext(ctx context.Context, event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return p.projectContext(ctx, event)
}

type cleanupRecordProjector struct {
	records  func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)
	cleanup  func(*cerebrov1.EventEnvelope) ([]string, error)
	requests func(*cerebrov1.EventEnvelope) ([]ports.ProjectionCleanupRequest, error)
}

func (p cleanupRecordProjector) ProjectRecords(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return p.records(event)
}

func (p cleanupRecordProjector) ProjectCleanupRecords(event *cerebrov1.EventEnvelope) ([]string, error) {
	if p.cleanup == nil {
		return nil, nil
	}
	return p.cleanup(event)
}

func (p cleanupRecordProjector) ProjectCleanupRequests(event *cerebrov1.EventEnvelope) ([]ports.ProjectionCleanupRequest, error) {
	if p.requests == nil {
		return nil, nil
	}
	return p.requests(event)
}

type retractionProjector struct {
	recordProjectorFunc
	retractions []*ports.ProjectedLink
}

func (p retractionProjector) ProjectRetractions(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLink, error) {
	return p.retractions, nil
}

type linkSetProjector struct {
	recordProjectorFunc
	linkSets func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error)
}

func (p linkSetProjector) ProjectLinkSets(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
	if p.linkSets == nil {
		return nil, nil
	}
	return p.linkSets(event)
}

type recordingProjectionGraphStore struct {
	entities        map[string]*ports.ProjectedEntity
	links           map[string]*ports.ProjectedLink
	upsertLinkErr   error
	deletedEntities map[string]struct{}
	deletedLinks    map[string]*ports.ProjectedLink
	cleanupRequests []ports.ProjectionCleanupRequest

	// linkSetObservations/linkSetLinks model the Neo4j store's guarded
	// Contract C9 semantics faithfully (not just recording calls) so
	// graphingest-level tests can prove retraction/no-op/survival behavior
	// without a database: each owner/relation/direction/tenant/source/
	// runtime scope keeps the last applied Observation and desired links,
	// keyed by the other endpoint's URN.
	linkSetObservations map[string]map[string]string
	linkSetLinks        map[string]map[string]*ports.ProjectedLink
	linkSetCalls        int
	linkSetSetsReceived int
	replaceLinkSetsErr  error

	// callOrder records the sequence of write-method calls so tests can
	// assert that link sets are applied after entity upserts.
	callOrder []string
}

type checkpointProjectionRunStore struct {
	stubRunStore
	checkpointProjectionGraphStore
}

func (s *checkpointProjectionRunStore) Ping(ctx context.Context) error {
	return s.stubRunStore.Ping(ctx)
}

func (s *recordingProjectionGraphStore) Ping(context.Context) error { return nil }

func (s *recordingProjectionGraphStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	s.callOrder = append(s.callOrder, "entity")
	if s.entities == nil {
		s.entities = map[string]*ports.ProjectedEntity{}
	}
	s.entities[entity.URN] = entity
	return nil
}

func (s *recordingProjectionGraphStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	s.callOrder = append(s.callOrder, "link")
	if s.upsertLinkErr != nil {
		return s.upsertLinkErr
	}
	if s.links == nil {
		s.links = map[string]*ports.ProjectedLink{}
	}
	s.links[link.FromURN+"|"+link.Relation+"|"+link.ToURN] = link
	return nil
}

// ReplaceProjectedLinkSets applies each set only when its Observation is not
// older than the scope's last applied one, then replaces that scope's
// desired links wholesale — mirroring the Neo4j store's guarded transaction
// (retract links the new set drops, keep/merge links it still wants). An
// Incomplete set only advances the scope's observation guard: its link
// context is unavailable or truncated, so it never retracts, asserts, or
// materializes anything (Contract G1). Once a set is accepted and not
// Incomplete, its Endpoints are CreateOnly-materialized into s.entities
// (R06, never overwriting an existing entity) before links are recorded,
// so tests can prove a stale or losing set's Endpoints never reach the
// store.
func (s *recordingProjectionGraphStore) ReplaceProjectedLinkSets(_ context.Context, sets []*ports.ProjectedLinkSet) error {
	s.callOrder = append(s.callOrder, "linkset")
	s.linkSetCalls++
	s.linkSetSetsReceived += len(sets)
	if s.replaceLinkSetsErr != nil {
		return s.replaceLinkSetsErr
	}
	if s.linkSetObservations == nil {
		s.linkSetObservations = map[string]map[string]string{}
	}
	if s.linkSetLinks == nil {
		s.linkSetLinks = map[string]map[string]*ports.ProjectedLink{}
	}
	for _, set := range sets {
		if err := ports.ValidateProjectedLinkSetEndpoints(set); err != nil {
			return err
		}
		key := projectedLinkSetKey(set)
		if stored, ok := s.linkSetObservations[key]; ok && projectionmeta.CompareObservations(stored, set.Observation) == projectionmeta.ObservationOlder {
			continue
		}
		if set.Incomplete {
			s.linkSetObservations[key] = set.Observation
			continue
		}
		if s.entities == nil {
			s.entities = map[string]*ports.ProjectedEntity{}
		}
		for _, endpoint := range set.Endpoints {
			if endpoint == nil {
				continue
			}
			if _, exists := s.entities[endpoint.URN]; exists {
				continue
			}
			s.entities[endpoint.URN] = endpoint
		}
		desired := make(map[string]*ports.ProjectedLink, len(set.Links))
		for _, link := range set.Links {
			other := link.ToURN
			if !set.Outgoing {
				other = link.FromURN
			}
			desired[other] = link
		}
		s.linkSetLinks[key] = desired
		s.linkSetObservations[key] = set.Observation
	}
	return nil
}

var _ ports.ProjectionLinkSetStore = (*recordingProjectionGraphStore)(nil)

type batchRecordingProjectionGraphStore struct {
	recordingProjectionGraphStore
	batchEntityCalls       int
	batchLinkCalls         int
	batchEntityDeleteCalls int
	batchLinkDeleteCalls   int
}

func (s *batchRecordingProjectionGraphStore) UpsertProjectedEntities(ctx context.Context, entities []*ports.ProjectedEntity) error {
	s.batchEntityCalls++
	for _, entity := range entities {
		if err := s.UpsertProjectedEntity(ctx, entity); err != nil {
			return err
		}
	}
	return nil
}

func (s *batchRecordingProjectionGraphStore) UpsertProjectedLinks(ctx context.Context, links []*ports.ProjectedLink) error {
	s.batchLinkCalls++
	for _, link := range links {
		if err := s.UpsertProjectedLink(ctx, link); err != nil {
			return err
		}
	}
	return nil
}

func (s *batchRecordingProjectionGraphStore) DeleteProjectedEntities(ctx context.Context, urns []string) error {
	s.batchEntityDeleteCalls++
	for _, urn := range urns {
		if err := s.DeleteProjectedEntity(ctx, urn); err != nil {
			return err
		}
	}
	return nil
}

func (s *batchRecordingProjectionGraphStore) DeleteProjectedLinks(ctx context.Context, links []*ports.ProjectedLink) error {
	s.batchLinkDeleteCalls++
	for _, link := range links {
		if err := s.DeleteProjectedLink(ctx, link); err != nil {
			return err
		}
	}
	return nil
}

var _ ports.ProjectionGraphBatchStore = (*batchRecordingProjectionGraphStore)(nil)
var _ ports.ProjectionEntityBatchDeleter = (*batchRecordingProjectionGraphStore)(nil)
var _ ports.ProjectionLinkBatchDeleter = (*batchRecordingProjectionGraphStore)(nil)

type checkpointProjectionGraphStore struct {
	recordingProjectionGraphStore
	checkpoints map[string]graphstore.IngestCheckpoint
}

func (s *checkpointProjectionGraphStore) GetIngestCheckpoint(_ context.Context, id string) (graphstore.IngestCheckpoint, bool, error) {
	checkpoint, ok := s.checkpoints[id]
	return checkpoint, ok, nil
}

func (s *checkpointProjectionGraphStore) PutIngestCheckpoint(_ context.Context, checkpoint graphstore.IngestCheckpoint) error {
	if s.checkpoints == nil {
		s.checkpoints = map[string]graphstore.IngestCheckpoint{}
	}
	s.checkpoints[checkpoint.ID] = checkpoint
	return nil
}

type graphingestRuntimeStore struct {
	runtimes map[string]*cerebrov1.SourceRuntime
	err      error
}

type graphingestLeaseRuntimeStore struct {
	*graphingestRuntimeStore
	available    bool
	acquireCalls int
	renewCalls   int
	releaseCalls int
}

func (s *graphingestLeaseRuntimeStore) AcquireSourceRuntimeLease(context.Context, string, string, time.Duration) (bool, error) {
	s.acquireCalls++
	return s.available, nil
}

func (s *graphingestLeaseRuntimeStore) RenewSourceRuntimeLease(context.Context, string, string, time.Duration) (bool, error) {
	s.renewCalls++
	return s.available, nil
}

func (s *graphingestLeaseRuntimeStore) ReleaseSourceRuntimeLease(context.Context, string, string) error {
	s.releaseCalls++
	return nil
}

func (s *graphingestRuntimeStore) Ping(context.Context) error { return s.err }

func (s *graphingestRuntimeStore) PutSourceRuntime(_ context.Context, runtime *cerebrov1.SourceRuntime) error {
	if s.err != nil {
		return s.err
	}
	if s.runtimes == nil {
		s.runtimes = map[string]*cerebrov1.SourceRuntime{}
	}
	s.runtimes[runtime.GetId()] = runtime
	return nil
}

func (s *graphingestRuntimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	if s.err != nil {
		return nil, s.err
	}
	runtime, ok := s.runtimes[id]
	if !ok {
		return nil, ports.ErrSourceRuntimeNotFound
	}
	return runtime, nil
}

func TestRunRuntimeStopsBeforeGraphWritesWhenRuntimeLeaseIsBusy(t *testing.T) {
	runtimeStore := &graphingestLeaseRuntimeStore{
		graphingestRuntimeStore: &graphingestRuntimeStore{},
		available:               false,
	}
	runStore := &stubRunStore{}
	projector := recordProjectorFunc(func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		t.Fatal("projector called without a runtime lease")
		return nil, nil, nil
	})

	_, err := New(nil, runtimeStore, projector, runStore).RunRuntime(context.Background(), RuntimeRequest{RuntimeID: "runtime-a"})
	if !errors.Is(err, sourceruntime.ErrSyncInProgress) {
		t.Fatalf("RunRuntime() error = %v, want %v", err, sourceruntime.ErrSyncInProgress)
	}
	if runtimeStore.acquireCalls != 1 || runtimeStore.renewCalls != 0 || runtimeStore.releaseCalls != 0 {
		t.Fatalf("lease calls = acquire:%d renew:%d release:%d, want 1/0/0", runtimeStore.acquireCalls, runtimeStore.renewCalls, runtimeStore.releaseCalls)
	}
	if len(runStore.putRuns) != 0 {
		t.Fatalf("graph ingest runs = %#v, want no graph mutation without the runtime lease", runStore.putRuns)
	}
	if got := graphIngestTelemetryErrorKind(err); got != "sync_in_progress" {
		t.Fatalf("graphIngestTelemetryErrorKind() = %q, want sync_in_progress", got)
	}
}

func TestGraphIngestTelemetryClassifiesRuntimeLeaseLoss(t *testing.T) {
	err := fmt.Errorf("release graph ingest lease: %w", ports.ErrSourceRuntimeLeaseLost)
	if got := graphIngestTelemetryErrorKind(err); got != "lease_lost" {
		t.Fatalf("graphIngestTelemetryErrorKind() = %q, want lease_lost", got)
	}
}

func TestRunRuntimeUsesCallerHeldRuntimeLease(t *testing.T) {
	runtimeStore := &graphingestLeaseRuntimeStore{
		graphingestRuntimeStore: &graphingestRuntimeStore{},
		available:               false,
	}
	runStore := &stubRunStore{}
	service := New(nil, runtimeStore, recordProjectorFunc(func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return nil, nil, nil
	}), runStore)

	_, err := service.RunRuntime(context.Background(), RuntimeRequest{RuntimeID: "missing", RuntimeLeaseHeld: true})
	if !errors.Is(err, ports.ErrSourceRuntimeNotFound) {
		t.Fatalf("RunRuntime() error = %v, want runtime lookup failure after caller-held lease bypass", err)
	}
	if runtimeStore.acquireCalls != 0 || runtimeStore.releaseCalls != 0 {
		t.Fatalf("lease calls = acquire:%d release:%d, want caller-held lease untouched", runtimeStore.acquireCalls, runtimeStore.releaseCalls)
	}
	if len(runStore.putRuns) != 2 {
		t.Fatalf("graph ingest run updates = %d, want running and failed records", len(runStore.putRuns))
	}
}

func TestRunRuntimeHonorsOrchestratorPageLimit(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(&multiCursorPagedSource{
		id:    "paged",
		pages: graphIngestTestPages(8, "paged"),
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	runtimeStore := &graphingestRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"runtime-paged": {
				Id:       "runtime-paged",
				SourceId: "paged",
				TenantId: "writer",
			},
		},
	}
	store := &checkpointProjectionRunStore{}
	service := New(registry, runtimeStore, recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return []*ports.ProjectedEntity{{
			URN:        "urn:cerebro:writer:paged:" + event.GetId(),
			TenantID:   event.GetTenantId(),
			SourceID:   event.GetSourceId(),
			RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
			EntityType: "paged.event",
			Label:      event.GetId(),
		}}, nil, nil
	}), store)

	orchestratorResult, err := service.RunRuntime(context.Background(), RuntimeRequest{
		RuntimeID:        "runtime-paged",
		PageLimit:        MaxPageLimit,
		Trigger:          "orchestrator",
		RuntimeLeaseHeld: true,
	})
	if err != nil {
		t.Fatalf("RunRuntime(orchestrator) error = %v", err)
	}
	if orchestratorResult.Ingest == nil {
		t.Fatal("RunRuntime(orchestrator) ingest = nil")
	}
	if orchestratorResult.Ingest.PagesRead != 8 || orchestratorResult.Ingest.EventsRead != 8 {
		t.Fatalf("orchestrator pages/events = %d/%d, want the configured 8/8", orchestratorResult.Ingest.PagesRead, orchestratorResult.Ingest.EventsRead)
	}
	if orchestratorResult.Ingest.NextCursor != "" || !orchestratorResult.Ingest.CheckpointComplete {
		t.Fatalf("orchestrator checkpoint = next:%q complete:%t, want complete", orchestratorResult.Ingest.NextCursor, orchestratorResult.Ingest.CheckpointComplete)
	}

	manualResult, err := service.RunRuntime(context.Background(), RuntimeRequest{
		RuntimeID:        "runtime-paged",
		PageLimit:        6,
		ResetCheckpoint:  true,
		Trigger:          "manual",
		RuntimeLeaseHeld: true,
	})
	if err != nil {
		t.Fatalf("RunRuntime(manual) error = %v", err)
	}
	if manualResult.Ingest == nil {
		t.Fatal("RunRuntime(manual) ingest = nil")
	}
	if manualResult.Ingest.PagesRead != 6 || manualResult.Ingest.EventsRead != 6 {
		t.Fatalf("manual pages/events = %d/%d, want 6/6", manualResult.Ingest.PagesRead, manualResult.Ingest.EventsRead)
	}
	if manualResult.Ingest.NextCursor != "page-6" {
		t.Fatalf("manual next cursor = %q, want page-6", manualResult.Ingest.NextCursor)
	}
}

type singlePageSource struct {
	id     string
	events []*cerebrov1.EventEnvelope
}

type authoritativeSinglePageSource struct{ *singlePageSource }

func (*authoritativeSinglePageSource) SupportsAuthoritativeProjectionReconciliation(sourcecdk.Config) bool {
	return true
}

func (s *singlePageSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: s.id, Name: "Single Page"}
}

func (s *singlePageSource) Check(context.Context, sourcecdk.Config) error { return nil }

func (s *singlePageSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s *singlePageSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{Events: s.events}, nil
}

type cursorPagedSource struct {
	id    string
	pages [][]*cerebrov1.EventEnvelope
}

type multiCursorPagedSource struct {
	id    string
	pages [][]*cerebrov1.EventEnvelope
}

func (s *cursorPagedSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: s.id, Name: "Cursor Paged"}
}

func (s *cursorPagedSource) Check(context.Context, sourcecdk.Config) error { return nil }

func (s *cursorPagedSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s *cursorPagedSource) Read(_ context.Context, _ sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	page := 0
	if cursor != nil && cursor.GetOpaque() == "page-1" {
		page = 1
	}
	pull := sourcecdk.Pull{Events: s.pages[page]}
	if page+1 < len(s.pages) {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: "page-1"}
	}
	return pull, nil
}

func (s *multiCursorPagedSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: s.id, Name: "Multi Cursor Paged"}
}

func (s *multiCursorPagedSource) Check(context.Context, sourcecdk.Config) error { return nil }

func (s *multiCursorPagedSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s *multiCursorPagedSource) Read(_ context.Context, _ sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	page := 0
	if cursor != nil {
		index, err := strconv.Atoi(strings.TrimPrefix(cursor.GetOpaque(), "page-"))
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		page = index
	}
	if page < 0 || page >= len(s.pages) {
		return sourcecdk.Pull{}, fmt.Errorf("page %d out of range", page)
	}
	pull := sourcecdk.Pull{Events: s.pages[page]}
	if page+1 < len(s.pages) {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: fmt.Sprintf("page-%d", page+1)}
	}
	return pull, nil
}

func graphIngestTestPages(count int, sourceID string) [][]*cerebrov1.EventEnvelope {
	pages := make([][]*cerebrov1.EventEnvelope, 0, count)
	for index := 0; index < count; index++ {
		pages = append(pages, []*cerebrov1.EventEnvelope{{
			Id:       fmt.Sprintf("event-%d", index+1),
			SourceId: sourceID,
		}})
	}
	return pages
}

func (s *recordingProjectionGraphStore) DeleteProjectedEntity(_ context.Context, urn string) error {
	if s.deletedEntities == nil {
		s.deletedEntities = map[string]struct{}{}
	}
	s.deletedEntities[urn] = struct{}{}
	delete(s.entities, urn)
	for key, link := range s.links {
		if link.FromURN == urn || link.ToURN == urn {
			delete(s.links, key)
		}
	}
	return nil
}

func (s *recordingProjectionGraphStore) DeleteProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	if s.deletedLinks == nil {
		s.deletedLinks = map[string]*ports.ProjectedLink{}
	}
	key := link.FromURN + "|" + link.Relation + "|" + link.ToURN
	s.deletedLinks[key] = link
	if s.links != nil {
		delete(s.links, key)
	}
	return nil
}

func (s *recordingProjectionGraphStore) CleanupProjectedEntities(_ context.Context, request ports.ProjectionCleanupRequest) (ports.ProjectionCleanupResult, error) {
	s.cleanupRequests = append(s.cleanupRequests, request)
	var result ports.ProjectionCleanupResult
	limit := projectionCleanupBatchLimit(request)
	for key, entity := range s.entities {
		if result.EntitiesDeleted >= limit {
			break
		}
		if !projectionCleanupTestMatches(request, entity) {
			continue
		}
		delete(s.entities, key)
		result.EntitiesDeleted++
	}
	for key, link := range s.links {
		if _, ok := s.entities[link.FromURN]; !ok {
			delete(s.links, key)
			result.LinksDeleted++
			continue
		}
		if _, ok := s.entities[link.ToURN]; !ok {
			delete(s.links, key)
			result.LinksDeleted++
		}
	}
	return result, nil
}

func (s *recordingProjectionGraphStore) CleanupProjectedRuntimeLinks(_ context.Context, request ports.ProjectionRuntimeLinkReconciliationRequest) (ports.ProjectionLinkCleanupResult, error) {
	var result ports.ProjectionLinkCleanupResult
	limit := request.Limit
	if limit == 0 {
		limit = defaultCleanupLimit
	}
	for key, link := range s.links {
		if result.LinksDeleted >= limit || link == nil || link.TenantID != request.TenantID || link.SourceID != request.SourceID || link.RuntimeID != request.RuntimeID || !slices.Contains(request.Relations, link.Relation) {
			continue
		}
		if link.Attributes[projectionReconciliationAttribute] == request.ReconciliationID {
			continue
		}
		result.LinksMatched++
		if !request.DryRun {
			delete(s.links, key)
			result.LinksDeleted++
		}
	}
	return result, nil
}

func TestIngestSourceReconcilesStaleMaterialLinksAfterCompleteAuthoritativePass(t *testing.T) {
	source := &authoritativeSinglePageSource{&singlePageSource{id: "authoritative", events: []*cerebrov1.EventEnvelope{{Id: "event-current", SourceId: "authoritative"}}}}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatal(err)
	}
	staleKey := "urn:resource|can_reach|urn:stale"
	store := &checkpointProjectionGraphStore{recordingProjectionGraphStore: recordingProjectionGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			"urn:resource": {URN: "urn:resource"},
			"urn:stale":    {URN: "urn:stale"},
		},
		links: map[string]*ports.ProjectedLink{
			staleKey: {TenantID: "tenant", SourceID: "authoritative", RuntimeID: "runtime-a", FromURN: "urn:resource", Relation: "can_reach", ToURN: "urn:stale", Attributes: map[string]string{}},
		},
	}}
	projector := recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		current := &ports.ProjectedEntity{URN: "urn:current", TenantID: event.GetTenantId(), SourceID: event.GetSourceId(), RuntimeID: "runtime-a", EntityType: "resource", Label: "current"}
		resource := &ports.ProjectedEntity{URN: "urn:resource", TenantID: event.GetTenantId(), SourceID: event.GetSourceId(), RuntimeID: "runtime-a", EntityType: "resource", Label: "resource"}
		return []*ports.ProjectedEntity{resource, current}, []*ports.ProjectedLink{{TenantID: event.GetTenantId(), SourceID: event.GetSourceId(), RuntimeID: "runtime-a", FromURN: resource.URN, Relation: "can_reach", ToURN: current.URN, Attributes: map[string]string{}}}, nil
	})
	service := New(registry, nil, projector, store)
	if !service.supportsAuthoritativeMaterialLinkReconciliation("authoritative", sourcecdk.Config{}) {
		t.Fatal("authoritative source/store/projector did not enable reconciliation")
	}
	result, err := service.ingestSource(context.Background(), sourceRequest{
		SourceID: "authoritative", RuntimeID: "runtime-a", TenantID: "tenant", PageLimit: 1,
		CheckpointEnabled: true, CheckpointID: "checkpoint-a", ResetCheckpoint: true,
		ReconcileMaterialLinks: true, ReconciliationSupported: true, ProjectionReconciliationID: "reconcile-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	current := store.links["urn:resource|can_reach|urn:current"]
	if !result.MaterialLinkReconciliationCompleted || result.StaleMaterialLinksDeleted != 1 || store.links[staleKey] != nil || current == nil || current.Attributes[projectionReconciliationAttribute] != "reconcile-1" {
		t.Fatalf("reconciliation result=%#v links=%#v", result, store.links)
	}
}

func projectionCleanupTestMatches(request ports.ProjectionCleanupRequest, entity *ports.ProjectedEntity) bool {
	if request.TenantID != "" && entity.TenantID != request.TenantID {
		return false
	}
	if request.SourceID != "" && entity.SourceID != request.SourceID {
		return false
	}
	if request.RuntimeID != "" && entity.RuntimeID != request.RuntimeID {
		return false
	}
	if len(request.EntityTypes) != 0 && !slices.Contains(request.EntityTypes, entity.EntityType) {
		return false
	}
	if len(request.URNPrefixes) == 0 {
		return true
	}
	for _, prefix := range request.URNPrefixes {
		if strings.HasPrefix(entity.URN, prefix) {
			return true
		}
	}
	return false
}

func TestSensitiveConfigKeyTreatsSecretMarkersAsSensitive(t *testing.T) {
	for _, key := range []string{"key", "api_key", "apiKey", "access_key_id", "secret_access_key", "private_key", "privateKey", "signing_key"} {
		if !sensitiveConfigKey(key) {
			t.Fatalf("sensitiveConfigKey(%q) = false, want true", key)
		}
	}
}

func TestConfigHashIgnoresSensitiveKeyValues(t *testing.T) {
	left := configHash(map[string]string{
		"apiKey":            "first",
		"secret_access_key": "first",
		"domain":            "writer.okta.com",
	})
	right := configHash(map[string]string{
		"apiKey":            "second",
		"secret_access_key": "second",
		"domain":            "writer.okta.com",
	})
	if left != right {
		t.Fatalf("configHash() differed when only sensitive keys changed")
	}
}

func TestConfigHashIgnoresInternalRuntimeMetadata(t *testing.T) {
	base := configHash(map[string]string{"domain": "writer.okta.com"})
	withInternal := configHash(map[string]string{
		"domain":                               "writer.okta.com",
		sourceconfig.RuntimeTenantIDKey:        "writer",
		sourceconfig.AWSAssumeRoleAllowlistKey: "writer=arn:aws:iam::123456789012:role/cerebro-org-scan-role",
	})
	if base != withInternal {
		t.Fatal("configHash() changed when only internal runtime metadata changed")
	}
}

func TestConfigHashIncludesNonSecretSelectorKeys(t *testing.T) {
	for _, key := range []string{"region", "lookup_key", "group_key"} {
		left := configHash(map[string]string{key: "first", "domain": "writer.example.com"})
		right := configHash(map[string]string{key: "second", "domain": "writer.example.com"})
		if left == right {
			t.Fatalf("configHash() ignored non-secret selector key %q", key)
		}
	}
}

func TestRuntimeCheckpointIDDistinguishesOriginalRuntimeIDs(t *testing.T) {
	first := runtimeCheckpointID(RuntimeRequest{}, &cerebrov1.SourceRuntime{Id: "writer_okta_users"}, map[string]string{"domain": "writer.okta.com"})
	second := runtimeCheckpointID(RuntimeRequest{}, &cerebrov1.SourceRuntime{Id: "writer-okta-users"}, map[string]string{"domain": "writer.okta.com"})
	if first == second {
		t.Fatalf("runtimeCheckpointID() collided for distinct runtime ids: %q", first)
	}
	if !strings.HasPrefix(first, "runtime:") || !strings.HasPrefix(second, "runtime:") {
		t.Fatalf("runtimeCheckpointID() = %q, %q; want runtime prefix", first, second)
	}
}

func TestRuntimeCheckpointStatusReportsFreshCompletedCheckpoint(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-github-audit",
		SourceId: "github",
		TenantId: "writer",
		Config:   map[string]string{"org": "WriterInternal"},
	}
	graphStore := &checkpointProjectionGraphStore{}
	service := &Service{
		runtimeStore: &graphingestRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{runtime.GetId(): runtime},
		},
		graphStore: graphStore,
	}

	status, err := service.RuntimeCheckpointStatus(context.Background(), RuntimeRequest{RuntimeID: runtime.GetId()})
	if err != nil {
		t.Fatalf("RuntimeCheckpointStatus() error = %v", err)
	}
	if status.Found || status.Completed || status.CheckpointCurrent {
		t.Fatalf("missing checkpoint status = %#v, want not found and not current", status)
	}
	if status.CheckpointID == "" || !strings.HasPrefix(status.CheckpointID, "runtime:") {
		t.Fatalf("CheckpointID = %q, want runtime checkpoint id", status.CheckpointID)
	}

	if err := graphStore.PutIngestCheckpoint(context.Background(), graphstore.IngestCheckpoint{
		ID:        status.CheckpointID,
		Completed: true,
	}); err != nil {
		t.Fatalf("PutIngestCheckpoint() error = %v", err)
	}
	status, err = service.RuntimeCheckpointStatus(context.Background(), RuntimeRequest{RuntimeID: runtime.GetId()})
	if err != nil {
		t.Fatalf("RuntimeCheckpointStatus() error = %v", err)
	}
	if !status.Found || !status.Completed || !status.CheckpointCurrent {
		t.Fatalf("completed checkpoint status = %#v, want found completed and current", status)
	}

	if err := graphStore.PutIngestCheckpoint(context.Background(), graphstore.IngestCheckpoint{
		ID:           status.CheckpointID,
		Completed:    true,
		CursorOpaque: "page-2",
	}); err != nil {
		t.Fatalf("PutIngestCheckpoint() error = %v", err)
	}
	status, err = service.RuntimeCheckpointStatus(context.Background(), RuntimeRequest{RuntimeID: runtime.GetId()})
	if err != nil {
		t.Fatalf("RuntimeCheckpointStatus() error = %v", err)
	}
	if !status.Found || !status.Completed || status.CheckpointCurrent {
		t.Fatalf("cursor checkpoint status = %#v, want found completed but not current", status)
	}
	if status.CursorOpaque != "page-2" {
		t.Fatalf("CursorOpaque = %q, want page-2", status.CursorOpaque)
	}
}

func TestIngestEventStampsTenantAndRuntime(t *testing.T) {
	event := ingestEvent(&cerebrov1.EventEnvelope{
		Id:       "event-1",
		TenantId: "old-tenant",
		Attributes: map[string]string{
			"existing": "value",
		},
	}, "writer", "writer-github")
	if got := event.GetTenantId(); got != "writer" {
		t.Fatalf("TenantId = %q, want writer", got)
	}
	if got := event.GetAttributes()[ports.EventAttributeSourceRuntimeID]; got != "writer-github" {
		t.Fatalf("source_runtime_id = %q, want writer-github", got)
	}
	if got := event.GetAttributes()["existing"]; got != "value" {
		t.Fatalf("existing attribute = %q, want value", got)
	}
}

func TestProjectResponseCoalescedUpsertsUniqueRecords(t *testing.T) {
	store := &recordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	projector := recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		if event.GetTenantId() != "writer" {
			t.Fatalf("event tenant = %q, want writer", event.GetTenantId())
		}
		if got := event.GetAttributes()[ports.EventAttributeSourceRuntimeID]; got != "writer-github-audit" {
			t.Fatalf("source_runtime_id = %q, want writer-github-audit", got)
		}
		return []*ports.ProjectedEntity{{
				URN:        "urn:cerebro:writer:github_org:WriterInternal",
				TenantID:   event.GetTenantId(),
				SourceID:   event.GetSourceId(),
				RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityType: "github.org",
				Label:      "WriterInternal",
				Attributes: map[string]string{"event_id": event.GetId()},
			}},
			[]*ports.ProjectedLink{{
				TenantID:  event.GetTenantId(),
				SourceID:  event.GetSourceId(),
				RuntimeID: event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				FromURN:   "urn:cerebro:writer:github_code_repository:WriterInternal/k8s",
				Relation:  "belongs_to",
				ToURN:     "urn:cerebro:writer:github_org:WriterInternal",
				Attributes: map[string]string{
					"event_id": event.GetId(),
				},
			}}, nil
	})
	result, err := service.projectResponseCoalesced(context.Background(), sourceRequest{
		SourceID:  "github",
		RuntimeID: "writer-github-audit",
		TenantID:  "writer",
	}, &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{
		{Id: "event-1", SourceId: "github"},
		{Id: "event-2", SourceId: "github"},
	}}, projector, nil)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if result.EventsRead != 2 {
		t.Fatalf("EventsRead = %d, want 2", result.EventsRead)
	}
	if result.EntitiesProjected != 1 {
		t.Fatalf("EntitiesProjected = %d, want 1 coalesced org upsert", result.EntitiesProjected)
	}
	if result.LinksProjected != 1 {
		t.Fatalf("LinksProjected = %d, want 1 coalesced repo->org link upsert", result.LinksProjected)
	}
	entity := store.entities["urn:cerebro:writer:github_org:WriterInternal"]
	if entity == nil {
		t.Fatal("coalesced org entity missing")
	}
	if got := entity.Attributes["event_id"]; got != "event-2" {
		t.Fatalf("coalesced entity event_id = %q, want latest event-2", got)
	}
	link := store.links["urn:cerebro:writer:github_code_repository:WriterInternal/k8s|belongs_to|urn:cerebro:writer:github_org:WriterInternal"]
	if link == nil {
		t.Fatal("coalesced repo->org link missing")
	}
	if got := link.Attributes["event_id"]; got != "event-2" {
		t.Fatalf("coalesced link event_id = %q, want latest event-2", got)
	}
}

func TestProjectResponseCoalescedPrefersContextAwareRecords(t *testing.T) {
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "request-context")
	legacyCalled := false
	contextCalled := false
	projector := contextRecordProjector{
		recordProjectorFunc: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			legacyCalled = true
			return nil, nil, nil
		},
		projectContext: func(callCtx context.Context, _ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			contextCalled = true
			if got := callCtx.Value(contextKey{}); got != "request-context" {
				t.Fatalf("projection context value = %v, want request-context", got)
			}
			return nil, nil, nil
		},
	}
	service := &Service{graphStore: &recordingProjectionGraphStore{}}
	_, err := service.projectResponseCoalesced(ctx, sourceRequest{TenantID: "writer"}, &cerebrov1.ReadSourceResponse{
		Events: []*cerebrov1.EventEnvelope{{Id: "event-1"}},
	}, projector, nil)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if !contextCalled || legacyCalled {
		t.Fatalf("context projector called = %t, legacy projector called = %t", contextCalled, legacyCalled)
	}
}

func TestProjectResponseCoalescedUsesBatchStoreWhenAvailable(t *testing.T) {
	store := &batchRecordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	projector := recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return []*ports.ProjectedEntity{{
				URN:        "urn:cerebro:writer:github_org:WriterInternal",
				TenantID:   event.GetTenantId(),
				SourceID:   event.GetSourceId(),
				RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityType: "github.org",
				Label:      "WriterInternal",
				Attributes: map[string]string{"event_id": event.GetId()},
			}},
			[]*ports.ProjectedLink{{
				TenantID:   event.GetTenantId(),
				SourceID:   event.GetSourceId(),
				RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				FromURN:    "urn:cerebro:writer:github_code_repository:WriterInternal/k8s",
				Relation:   "belongs_to",
				ToURN:      "urn:cerebro:writer:github_org:WriterInternal",
				Attributes: map[string]string{"event_id": event.GetId()},
			}}, nil
	})
	result, err := service.projectResponseCoalesced(context.Background(), sourceRequest{
		SourceID:  "github",
		RuntimeID: "writer-github-audit",
		TenantID:  "writer",
	}, &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{
		{Id: "event-1", SourceId: "github"},
		{Id: "event-2", SourceId: "github"},
	}}, projector, nil)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if store.batchEntityCalls != 1 || store.batchLinkCalls != 1 {
		t.Fatalf("batch calls = entities %d links %d, want 1 and 1 (batch path used)", store.batchEntityCalls, store.batchLinkCalls)
	}
	if result.EntitiesProjected != 1 || result.LinksProjected != 1 {
		t.Fatalf("projected counts = entities %d links %d, want 1 and 1", result.EntitiesProjected, result.LinksProjected)
	}
	if entity := store.entities["urn:cerebro:writer:github_org:WriterInternal"]; entity == nil || entity.Attributes["event_id"] != "event-2" {
		t.Fatalf("coalesced entity = %#v, want latest event-2", entity)
	}
	if link := store.links["urn:cerebro:writer:github_code_repository:WriterInternal/k8s|belongs_to|urn:cerebro:writer:github_org:WriterInternal"]; link == nil || link.Attributes["event_id"] != "event-2" {
		t.Fatalf("coalesced link = %#v, want latest event-2", link)
	}
}

func TestProjectResponseCoalescedDeletesCleanupRecords(t *testing.T) {
	staleURN := "urn:cerebro:writer:okta_resource:access_token:token-123"
	staleLink := &ports.ProjectedLink{
		TenantID: "writer",
		SourceID: "okta",
		FromURN:  "urn:cerebro:writer:okta_application:0oa-client",
		Relation: "acted_on",
		ToURN:    staleURN,
	}
	store := &recordingProjectionGraphStore{
		entities: map[string]*ports.ProjectedEntity{staleURN: {
			URN:        staleURN,
			TenantID:   "writer",
			SourceID:   "okta",
			RuntimeID:  "okta-audit-runtime",
			EntityType: "okta.resource",
			Label:      "token-123",
		}},
		links: map[string]*ports.ProjectedLink{"urn:cerebro:writer:okta_application:0oa-client|acted_on|" + staleURN: staleLink},
	}
	service := &Service{graphStore: store}
	projector := cleanupRecordProjector{
		records: func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return []*ports.ProjectedEntity{{
					URN:        "urn:cerebro:writer:okta_application:0oa-client",
					TenantID:   event.GetTenantId(),
					SourceID:   event.GetSourceId(),
					RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
					EntityType: "okta.application",
					Label:      "Production Client",
				}},
				[]*ports.ProjectedLink{{
					TenantID:  event.GetTenantId(),
					SourceID:  event.GetSourceId(),
					RuntimeID: event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
					FromURN:   "urn:cerebro:writer:okta_actor:publicclientapp:0oa-client",
					Relation:  "acted_on",
					ToURN:     "urn:cerebro:writer:okta_application:0oa-client",
				}}, nil
		},
		cleanup: func(*cerebrov1.EventEnvelope) ([]string, error) {
			return []string{staleURN}, nil
		},
	}

	_, err := service.projectResponseCoalesced(context.Background(), sourceRequest{
		SourceID:  "okta",
		RuntimeID: "okta-audit-runtime",
		TenantID:  "writer",
	}, &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{{
		Id:       "okta-oauth-grant",
		SourceId: "okta",
	}}}, projector, nil)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if _, ok := store.deletedEntities[staleURN]; !ok {
		t.Fatalf("cleanup entity %q was not deleted", staleURN)
	}
	if _, ok := store.entities[staleURN]; ok {
		t.Fatalf("cleanup entity %q still present", staleURN)
	}
	if _, ok := store.links["urn:cerebro:writer:okta_application:0oa-client|acted_on|"+staleURN]; ok {
		t.Fatalf("stale cleanup link still present")
	}
	if _, ok := store.links["urn:cerebro:writer:okta_actor:publicclientapp:0oa-client|acted_on|urn:cerebro:writer:okta_application:0oa-client"]; !ok {
		t.Fatalf("replacement durable link missing")
	}
}

func TestProjectResponseCoalescedRunsCleanupRequestsOnce(t *testing.T) {
	staleURN := "urn:cerebro:writer:okta_resource:access_token:token-123"
	appURN := "urn:cerebro:writer:okta_application:0oa-client"
	store := &recordingProjectionGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			staleURN: {
				URN:        staleURN,
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.resource",
				Label:      "token-123",
			},
			appURN: {
				URN:        appURN,
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.application",
				Label:      "Production Client",
			},
		},
		links: map[string]*ports.ProjectedLink{
			appURN + "|acted_on|" + staleURN: {
				TenantID: "writer",
				SourceID: "okta",
				FromURN:  appURN,
				Relation: "acted_on",
				ToURN:    staleURN,
			},
		},
	}
	service := &Service{graphStore: store}
	projector := cleanupRecordProjector{
		records: func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return []*ports.ProjectedEntity{{
				URN:        appURN,
				TenantID:   event.GetTenantId(),
				SourceID:   event.GetSourceId(),
				RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityType: "okta.application",
				Label:      "Production Client",
			}}, nil, nil
		},
		requests: func(event *cerebrov1.EventEnvelope) ([]ports.ProjectionCleanupRequest, error) {
			return []ports.ProjectionCleanupRequest{{
				TenantID:    event.GetTenantId(),
				SourceID:    event.GetSourceId(),
				RuntimeID:   event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityTypes: []string{"okta.resource"},
				URNPrefixes: []string{"urn:cerebro:writer:okta_resource:access_token:"},
				Limit:       1000,
			}}, nil
		},
	}

	_, err := service.projectResponseCoalesced(context.Background(), sourceRequest{
		SourceID:  "okta",
		RuntimeID: "okta-audit-runtime",
		TenantID:  "writer",
	}, &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{
		{Id: "okta-oauth-grant-1", SourceId: "okta"},
		{Id: "okta-oauth-grant-2", SourceId: "okta"},
	}}, projector, nil)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if got := len(store.cleanupRequests); got != 1 {
		t.Fatalf("cleanup requests = %d, want 1 deduped request", got)
	}
	if _, ok := store.entities[staleURN]; ok {
		t.Fatalf("stale cleanup entity %q still present", staleURN)
	}
	if _, ok := store.links[appURN+"|acted_on|"+staleURN]; ok {
		t.Fatalf("stale cleanup link still present")
	}
	if _, ok := store.entities[appURN]; !ok {
		t.Fatalf("durable app entity was deleted")
	}
}

func TestProjectResponseCoalescedSkipsCompletedCleanupRequests(t *testing.T) {
	store := &recordingProjectionGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			"urn:cerebro:writer:okta_resource:access_token:token-123": {
				URN:        "urn:cerebro:writer:okta_resource:access_token:token-123",
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.resource",
				Label:      "token-123",
			},
		},
	}
	service := &Service{graphStore: store}
	projector := cleanupRecordProjector{
		records: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return nil, nil, nil
		},
		requests: func(event *cerebrov1.EventEnvelope) ([]ports.ProjectionCleanupRequest, error) {
			return []ports.ProjectionCleanupRequest{{
				TenantID:    event.GetTenantId(),
				SourceID:    event.GetSourceId(),
				RuntimeID:   event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityTypes: []string{"okta.resource"},
				URNPrefixes: []string{"urn:cerebro:writer:okta_resource:access_token:"},
				Limit:       1000,
			}}, nil
		},
	}
	completedCleanupRequests := map[string]struct{}{}
	request := sourceRequest{SourceID: "okta", RuntimeID: "okta-audit-runtime", TenantID: "writer"}
	response := func(id string) *cerebrov1.ReadSourceResponse {
		return &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{{Id: id, SourceId: "okta"}}}
	}

	if _, err := service.projectResponseCoalesced(context.Background(), request, response("okta-oauth-grant-page-1"), projector, completedCleanupRequests); err != nil {
		t.Fatalf("projectResponseCoalesced(page 1) error = %v", err)
	}
	if _, err := service.projectResponseCoalesced(context.Background(), request, response("okta-oauth-grant-page-2"), projector, completedCleanupRequests); err != nil {
		t.Fatalf("projectResponseCoalesced(page 2) error = %v", err)
	}
	if got := len(store.cleanupRequests); got != 1 {
		t.Fatalf("cleanup requests = %d, want 1 across pages", got)
	}
}

func TestProjectResponseCoalescedRunsCleanupRequestsUntilExhausted(t *testing.T) {
	store := &recordingProjectionGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			"urn:cerebro:writer:okta_resource:access_token:token-1": {
				URN:        "urn:cerebro:writer:okta_resource:access_token:token-1",
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.resource",
				Label:      "token-1",
			},
			"urn:cerebro:writer:okta_resource:access_token:token-2": {
				URN:        "urn:cerebro:writer:okta_resource:access_token:token-2",
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.resource",
				Label:      "token-2",
			},
		},
	}
	service := &Service{graphStore: store}
	projector := cleanupRecordProjector{
		records: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return nil, nil, nil
		},
		requests: func(event *cerebrov1.EventEnvelope) ([]ports.ProjectionCleanupRequest, error) {
			return []ports.ProjectionCleanupRequest{{
				TenantID:    event.GetTenantId(),
				SourceID:    event.GetSourceId(),
				RuntimeID:   event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityTypes: []string{"okta.resource"},
				URNPrefixes: []string{"urn:cerebro:writer:okta_resource:access_token:"},
				Limit:       1,
			}}, nil
		},
	}

	_, err := service.projectResponseCoalesced(context.Background(), sourceRequest{
		SourceID:  "okta",
		RuntimeID: "okta-audit-runtime",
		TenantID:  "writer",
	}, &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{{
		Id:       "okta-oauth-grant",
		SourceId: "okta",
	}}}, projector, nil)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if got := len(store.cleanupRequests); got != 3 {
		t.Fatalf("cleanup calls = %d, want 3 calls to confirm exhaustion", got)
	}
	if len(store.entities) != 0 {
		t.Fatalf("store retained %d cleanup entities", len(store.entities))
	}
}

func TestProjectResponseCoalescedDeletesProjectedRetractions(t *testing.T) {
	staleLink := &ports.ProjectedLink{
		TenantID: "writer",
		SourceID: "kolide",
		FromURN:  "urn:cerebro:writer:kolide_device:device-1",
		Relation: "owned_by",
		ToURN:    "urn:cerebro:writer:identity:login:user-1",
	}
	key := staleLink.FromURN + "|" + staleLink.Relation + "|" + staleLink.ToURN
	store := &recordingProjectionGraphStore{links: map[string]*ports.ProjectedLink{key: staleLink}}
	service := &Service{graphStore: store}
	projector := retractionProjector{
		recordProjectorFunc: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return nil, nil, nil
		},
		retractions: []*ports.ProjectedLink{staleLink},
	}

	_, err := service.projectResponseCoalesced(context.Background(), sourceRequest{
		SourceID:  "kolide",
		RuntimeID: "kolide-runtime",
		TenantID:  "writer",
	}, &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{{
		Id:       "kolide-device",
		SourceId: "kolide",
	}}}, projector, nil)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if _, ok := store.deletedLinks[key]; !ok {
		t.Fatalf("stale link was not deleted: %#v", store.deletedLinks)
	}
	if _, ok := store.links[key]; ok {
		t.Fatalf("stale link remains after deletion")
	}
}

func TestProjectResponseCoalescedUsesBatchDeleters(t *testing.T) {
	staleURN := "urn:cerebro:writer:device:stale"
	staleLink := &ports.ProjectedLink{
		TenantID: "writer", SourceID: "endpoint", RuntimeID: "endpoint-runtime",
		FromURN: "urn:cerebro:writer:device:active", Relation: "owned_by", ToURN: "urn:cerebro:writer:identity:user-1",
	}
	store := &batchRecordingProjectionGraphStore{recordingProjectionGraphStore: recordingProjectionGraphStore{
		entities: map[string]*ports.ProjectedEntity{staleURN: {URN: staleURN}},
		links:    map[string]*ports.ProjectedLink{staleLink.FromURN + "|" + staleLink.Relation + "|" + staleLink.ToURN: staleLink},
	}}
	projector := struct {
		cleanupRecordProjector
		retractionProjector
	}{
		cleanupRecordProjector: cleanupRecordProjector{
			records: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
				return nil, nil, nil
			},
			cleanup: func(*cerebrov1.EventEnvelope) ([]string, error) { return []string{staleURN}, nil },
		},
		retractionProjector: retractionProjector{retractions: []*ports.ProjectedLink{staleLink}},
	}
	// Compose the optional cleanup and retraction capabilities explicitly because
	// both must be visible on the same projector value.
	combined := batchCleanupRetractionProjector{cleanup: projector.cleanupRecordProjector, retractions: projector.retractionProjector}
	service := &Service{graphStore: store}
	if _, err := service.projectResponseCoalesced(context.Background(), sourceRequest{TenantID: "writer"}, &cerebrov1.ReadSourceResponse{
		Events: []*cerebrov1.EventEnvelope{{Id: "event-1", SourceId: "endpoint"}},
	}, combined, nil); err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if store.batchEntityDeleteCalls != 1 || store.batchLinkDeleteCalls != 1 {
		t.Fatalf("batch delete calls = entities %d links %d, want 1 and 1", store.batchEntityDeleteCalls, store.batchLinkDeleteCalls)
	}
}

type batchCleanupRetractionProjector struct {
	cleanup     cleanupRecordProjector
	retractions retractionProjector
}

func (p batchCleanupRetractionProjector) ProjectRecords(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return p.cleanup.ProjectRecords(event)
}

func (p batchCleanupRetractionProjector) ProjectCleanupRecords(event *cerebrov1.EventEnvelope) ([]string, error) {
	return p.cleanup.ProjectCleanupRecords(event)
}

func (p batchCleanupRetractionProjector) ProjectRetractions(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLink, error) {
	return p.retractions.ProjectRetractions(event)
}

func TestProjectResponseCoalescedPreservesNewestObservationAttributes(t *testing.T) {
	store := &recordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	projector := recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		at := "2026-05-11T10:00:00Z"
		if event.GetId() == "older-event" {
			at = "2026-05-10T10:00:00Z"
		}
		return []*ports.ProjectedEntity{{
				URN:        "urn:cerebro:writer:github_user:alice",
				TenantID:   event.GetTenantId(),
				SourceID:   event.GetSourceId(),
				RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityType: "github.user",
				Label:      "alice",
				Attributes: map[string]string{
					"at":             at,
					"event_id":       event.GetId(),
					"login":          event.GetId(),
					"outcome_result": event.GetId(),
				},
			}},
			[]*ports.ProjectedLink{{
				TenantID:  event.GetTenantId(),
				SourceID:  event.GetSourceId(),
				RuntimeID: event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				FromURN:   "urn:cerebro:writer:github_user:alice",
				Relation:  "acted_on",
				ToURN:     "urn:cerebro:writer:github_code_repository:writer/cerebro",
				Attributes: map[string]string{
					"action":         "git.clone",
					"at":             at,
					"event_id":       event.GetId(),
					"event_type":     event.GetId(),
					"outcome_result": event.GetId(),
					"target":         event.GetId(),
				},
			}}, nil
	})
	_, err := service.projectResponseCoalesced(context.Background(), sourceRequest{
		SourceID:  "github",
		RuntimeID: "writer-github-audit",
		TenantID:  "writer",
	}, &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{
		{Id: "newer-event", SourceId: "github"},
		{Id: "older-event", SourceId: "github"},
	}}, projector, nil)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	entity := store.entities["urn:cerebro:writer:github_user:alice"]
	if entity == nil {
		t.Fatal("coalesced github.user entity missing")
	}
	if got := entity.Attributes["at"]; got != "2026-05-11T10:00:00Z" {
		t.Fatalf("coalesced entity at = %q, want newest timestamp", got)
	}
	if got := entity.Attributes["event_id"]; got != "newer-event" {
		t.Fatalf("coalesced entity event_id = %q, want newer-event coupled to newest observation", got)
	}
	if got := entity.Attributes["outcome_result"]; got != "newer-event" {
		t.Fatalf("coalesced entity outcome_result = %q, want newer-event coupled to newest observation", got)
	}
	if got := entity.Attributes["login"]; got != "older-event" {
		t.Fatalf("coalesced entity non-observation attribute login = %q, want older-event latest write", got)
	}
	link := store.links["urn:cerebro:writer:github_user:alice|acted_on|urn:cerebro:writer:github_code_repository:writer/cerebro"]
	if link == nil {
		t.Fatal("coalesced acted_on link missing")
	}
	if got := link.Attributes["at"]; got != "2026-05-11T10:00:00Z" {
		t.Fatalf("coalesced link at = %q, want newest timestamp", got)
	}
	if got := link.Attributes["event_id"]; got != "newer-event" {
		t.Fatalf("coalesced link event_id = %q, want newer-event coupled to newest observation", got)
	}
	if got := link.Attributes["event_type"]; got != "newer-event" {
		t.Fatalf("coalesced link event_type = %q, want newer-event coupled to newest observation", got)
	}
	if got := link.Attributes["outcome_result"]; got != "newer-event" {
		t.Fatalf("coalesced link outcome_result = %q, want newer-event coupled to newest observation", got)
	}
	if got := link.Attributes["target"]; got != "older-event" {
		t.Fatalf("coalesced link non-observation attribute target = %q, want older-event latest write", got)
	}
}

func TestMergeStringMapClearsOlderObservationMetadataMissingFromNewerAt(t *testing.T) {
	merged := mergeStringMap(
		map[string]string{
			"at":             "2026-05-10T10:00:00Z",
			"event_id":       "older-event",
			"outcome_reason": "older reason",
			"transaction_id": "older-txn",
			"target":         "repo",
		},
		map[string]string{
			"at":       "2026-05-11T10:00:00Z",
			"event_id": "newer-event",
		},
	)
	for key, want := range map[string]string{
		"at":       "2026-05-11T10:00:00Z",
		"event_id": "newer-event",
		"target":   "repo",
	} {
		if got := merged[key]; got != want {
			t.Fatalf("merged[%s] = %q, want %q", key, got, want)
		}
	}
	for _, key := range []string{"outcome_reason", "transaction_id"} {
		if got, exists := merged[key]; exists {
			t.Fatalf("merged[%s] = %q, want missing because newer observation omitted it", key, got)
		}
	}
}

// Strict-precedence entities keep their newest observation within a page: one
// vulnview.finding orders by `at`, and another by observation_version even
// when a higher version committed with an earlier `at`.
func TestProjectResponseCoalescedKeepsNewestStrictObservation(t *testing.T) {
	const atOrderedFindingURN = "urn:cerebro:writer:vulnview.finding:at-ordered"
	const versionOrderedFindingURN = "urn:cerebro:writer:vulnview.finding:version-ordered"
	observations := map[string]struct{ urn, at, version, status string }{
		"at-ordered-new":    {atOrderedFindingURN, "2026-11-02T10:00:00Z", "", "supported"},
		"at-ordered-old":    {atOrderedFindingURN, "2026-11-02T09:00:00Z", "", "clear"},
		"finding-v2":        {versionOrderedFindingURN, "2026-11-02T10:00:01Z", "2", "fixed"},
		"finding-v3":        {versionOrderedFindingURN, "2026-11-02T10:00:00Z", "3", "open"},
		"finding-v2-replay": {versionOrderedFindingURN, "2026-11-02T10:00:01Z", "2", "fixed"},
	}
	store := &recordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	projector := recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		observation := observations[event.GetId()]
		return []*ports.ProjectedEntity{{
			URN: observation.urn, TenantID: event.GetTenantId(), SourceID: event.GetSourceId(),
			EntityType: "vulnview.finding", Label: event.GetId(),
			Attributes: map[string]string{
				"at": observation.at, "observation_precedence": "strict", "observation_version": observation.version,
				"status": observation.status, "event_id": event.GetId(),
			},
		}}, nil, nil
	})
	events := make([]*cerebrov1.EventEnvelope, 0, len(observations))
	for _, id := range []string{"at-ordered-new", "at-ordered-old", "finding-v2", "finding-v3", "finding-v2-replay"} {
		events = append(events, &cerebrov1.EventEnvelope{Id: id, SourceId: "vulnview"})
	}
	if _, err := service.projectResponseCoalesced(context.Background(), sourceRequest{SourceID: "vulnview", RuntimeID: "writer-vulnview", TenantID: "writer"}, &cerebrov1.ReadSourceResponse{Events: events}, projector, nil); err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	for urn, want := range map[string]string{atOrderedFindingURN: "at-ordered-new", versionOrderedFindingURN: "finding-v3"} {
		entity := store.entities[urn]
		if entity == nil {
			t.Fatalf("coalesced entity %s missing", urn)
		}
		wantStatus := observations[want].status
		if entity.Label != want || entity.Attributes["event_id"] != want || entity.Attributes["status"] != wantStatus {
			t.Fatalf("coalesced %s = label %q event_id %q status %q, want the %s observation (status %q)", urn, entity.Label, entity.Attributes["event_id"], entity.Attributes["status"], want, wantStatus)
		}
	}
}

func TestIngestSourceReportsProgressAfterEachPersistedPage(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(&cursorPagedSource{
		id: "paged",
		pages: [][]*cerebrov1.EventEnvelope{
			{{Id: "event-1", SourceId: "paged"}},
			{{Id: "event-2", SourceId: "paged"}},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &checkpointProjectionGraphStore{}
	service := &Service{
		sourceService: sourceops.New(registry),
		graphStore:    store,
		projector: recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return []*ports.ProjectedEntity{{
				URN:        "urn:cerebro:writer:paged:" + event.GetId(),
				TenantID:   event.GetTenantId(),
				SourceID:   event.GetSourceId(),
				EntityType: "paged.entity",
				Label:      event.GetId(),
			}}, nil, nil
		}),
	}
	var snapshots []IngestResult
	result, err := service.ingestSource(context.Background(), sourceRequest{
		SourceID:          "paged",
		RuntimeID:         "runtime-1",
		TenantID:          "writer",
		PageLimit:         2,
		CheckpointEnabled: true,
		CheckpointID:      "checkpoint-1",
	}, func(progress *IngestResult) {
		snapshots = append(snapshots, *progress)
	})
	if err != nil {
		t.Fatalf("ingestSource() error = %v", err)
	}
	if result.PagesRead != 2 || result.EventsRead != 2 || result.EntitiesProjected != 2 {
		t.Fatalf("result pages/events/entities = %d/%d/%d, want 2/2/2", result.PagesRead, result.EventsRead, result.EntitiesProjected)
	}
	if len(snapshots) != 2 {
		t.Fatalf("progress snapshots = %d, want 2", len(snapshots))
	}
	if snapshots[0].PagesRead != 1 || snapshots[0].EventsRead != 1 || !snapshots[0].CheckpointPersisted {
		t.Fatalf("first progress = %#v, want one persisted page", snapshots[0])
	}
	if snapshots[1].PagesRead != 2 || snapshots[1].EventsRead != 2 || !snapshots[1].CheckpointComplete {
		t.Fatalf("second progress = %#v, want completed second page", snapshots[1])
	}
}

func TestIngestSourceReturnsPartialCountersOnProjectionFailure(t *testing.T) {
	upsertErr := errors.New("neo4j timeout")
	registry, err := sourcecdk.NewRegistry(&singlePageSource{
		id: "partial",
		events: []*cerebrov1.EventEnvelope{{
			Id:       "event-1",
			SourceId: "partial",
		}},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &recordingProjectionGraphStore{upsertLinkErr: upsertErr}
	projector := recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return []*ports.ProjectedEntity{{
				URN:        "urn:cerebro:tenant:partial_entity:one",
				TenantID:   event.GetTenantId(),
				SourceID:   event.GetSourceId(),
				RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityType: "partial.entity",
				Label:      "one",
			}},
			[]*ports.ProjectedLink{{
				TenantID:  event.GetTenantId(),
				SourceID:  event.GetSourceId(),
				RuntimeID: event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				FromURN:   "urn:cerebro:tenant:partial_entity:one",
				Relation:  "related_to",
				ToURN:     "urn:cerebro:tenant:partial_entity:one",
			}}, nil
	})
	service := New(registry, nil, projector, store)

	result, err := service.ingestSource(context.Background(), sourceRequest{
		SourceID:  "partial",
		RuntimeID: "tenant-partial",
		TenantID:  "tenant",
		PageLimit: 1,
	})
	if !errors.Is(err, upsertErr) {
		t.Fatalf("ingestSource() error = %v, want %v", err, upsertErr)
	}
	if result == nil {
		t.Fatal("ingestSource() result = nil, want partial counters")
	}
	if result.PagesRead != 1 || result.EventsRead != 1 || result.EntitiesProjected != 1 || result.LinksProjected != 0 {
		t.Fatalf("partial counters = pages %d events %d entities %d links %d, want 1/1/1/0", result.PagesRead, result.EventsRead, result.EntitiesProjected, result.LinksProjected)
	}
}

func TestIngestSourceCanResetCompletedCheckpoint(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(&singlePageSource{
		id: "checkpointed",
		events: []*cerebrov1.EventEnvelope{{
			Id:       "event-1",
			SourceId: "checkpointed",
		}},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &checkpointProjectionGraphStore{
		checkpoints: map[string]graphstore.IngestCheckpoint{
			"checkpoint-1": {ID: "checkpoint-1", Completed: true},
		},
	}
	projector := recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return []*ports.ProjectedEntity{{
			URN:        "urn:cerebro:writer:checkpointed:event-1",
			TenantID:   event.GetTenantId(),
			SourceID:   event.GetSourceId(),
			RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
			EntityType: "checkpointed.event",
			Label:      event.GetId(),
		}}, nil, nil
	})
	service := New(registry, nil, projector, store)

	freshResult, err := service.ingestSource(context.Background(), sourceRequest{
		SourceID:          "checkpointed",
		RuntimeID:         "runtime-1",
		TenantID:          "writer",
		PageLimit:         1,
		CheckpointEnabled: true,
		CheckpointID:      "checkpoint-1",
	})
	if err != nil {
		t.Fatalf("ingestSource(default checkpoint) error = %v", err)
	}
	if !freshResult.CheckpointAlreadyFresh || freshResult.EventsRead != 0 {
		t.Fatalf("default checkpoint result fresh=%v events=%d, want already fresh with no reads", freshResult.CheckpointAlreadyFresh, freshResult.EventsRead)
	}

	resetResult, err := service.ingestSource(context.Background(), sourceRequest{
		SourceID:                 "checkpointed",
		RuntimeID:                "runtime-1",
		TenantID:                 "writer",
		PageLimit:                1,
		CheckpointEnabled:        true,
		CheckpointID:             "checkpoint-1",
		ResetCompletedCheckpoint: true,
	})
	if err != nil {
		t.Fatalf("ingestSource(reset completed checkpoint) error = %v", err)
	}
	if resetResult.CheckpointAlreadyFresh {
		t.Fatal("reset completed checkpoint was treated as already fresh")
	}
	if resetResult.PagesRead != 1 || resetResult.EventsRead != 1 || !resetResult.CheckpointPersisted {
		t.Fatalf("reset checkpoint result pages=%d events=%d persisted=%v, want 1/1/persisted", resetResult.PagesRead, resetResult.EventsRead, resetResult.CheckpointPersisted)
	}
}

func TestResetCompletedCheckpointClearsStoredFreshnessBeforeProjection(t *testing.T) {
	projectionErr := errors.New("projection failed")
	registry, err := sourcecdk.NewRegistry(&singlePageSource{
		id: "checkpointed",
		events: []*cerebrov1.EventEnvelope{{
			Id:       "event-1",
			SourceId: "checkpointed",
		}},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &checkpointProjectionGraphStore{
		checkpoints: map[string]graphstore.IngestCheckpoint{
			"checkpoint-1": {ID: "checkpoint-1", Completed: true},
		},
	}
	projector := recordProjectorFunc(func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return nil, nil, projectionErr
	})
	service := New(registry, nil, projector, store)

	result, err := service.ingestSource(context.Background(), sourceRequest{
		SourceID:                 "checkpointed",
		RuntimeID:                "runtime-1",
		TenantID:                 "writer",
		PageLimit:                1,
		CheckpointEnabled:        true,
		CheckpointID:             "checkpoint-1",
		ResetCompletedCheckpoint: true,
	})
	if !errors.Is(err, projectionErr) {
		t.Fatalf("ingestSource() error = %v, want %v", err, projectionErr)
	}
	if result.CheckpointPersisted {
		t.Fatal("failed projection should not report a persisted page checkpoint")
	}
	stored := store.checkpoints["checkpoint-1"]
	if stored.Completed {
		t.Fatal("stored checkpoint remained completed after reset marker")
	}

	freshCheck := &IngestResult{}
	var cursor *cerebrov1.SourceCursor
	if _, err := service.prepareCheckpoint(context.Background(), sourceRequest{
		SourceID:          "checkpointed",
		RuntimeID:         "runtime-1",
		TenantID:          "writer",
		PageLimit:         1,
		CheckpointEnabled: true,
		CheckpointID:      "checkpoint-1",
	}, freshCheck, &cursor); err != nil {
		t.Fatalf("prepareCheckpoint() error = %v", err)
	}
	if freshCheck.CheckpointAlreadyFresh {
		t.Fatal("cleared checkpoint was still treated as already fresh")
	}
}

func TestResetCheckpointClearsPartialCheckpointBeforeProjection(t *testing.T) {
	projectionErr := errors.New("projection failed")
	registry, err := sourcecdk.NewRegistry(&singlePageSource{
		id: "checkpointed",
		events: []*cerebrov1.EventEnvelope{{
			Id:       "event-1",
			SourceId: "checkpointed",
		}},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &checkpointProjectionGraphStore{
		checkpoints: map[string]graphstore.IngestCheckpoint{
			"checkpoint-1": {ID: "checkpoint-1", CursorOpaque: "2", Completed: false, PagesRead: 1, EventsRead: 1},
		},
	}
	projector := recordProjectorFunc(func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return nil, nil, projectionErr
	})
	service := New(registry, nil, projector, store)

	result, err := service.ingestSource(context.Background(), sourceRequest{
		SourceID:          "checkpointed",
		RuntimeID:         "runtime-1",
		TenantID:          "writer",
		PageLimit:         1,
		CheckpointEnabled: true,
		CheckpointID:      "checkpoint-1",
		ResetCheckpoint:   true,
	})
	if !errors.Is(err, projectionErr) {
		t.Fatalf("ingestSource() error = %v, want %v", err, projectionErr)
	}
	if result.CheckpointPersisted {
		t.Fatal("failed projection should not report a persisted page checkpoint")
	}
	stored := store.checkpoints["checkpoint-1"]
	if stored.CursorOpaque != "" || stored.Completed || stored.PagesRead != 0 || stored.EventsRead != 0 {
		t.Fatalf("stored checkpoint = %#v, want cleared reset marker", stored)
	}
}

func TestHealthFailedCountDoesNotDependOnPagingLimit(t *testing.T) {
	store := &stubRunStore{
		runs: []graphstore.IngestRun{
			{ID: "failed-1", Status: graphstore.IngestRunStatusFailed},
			{ID: "failed-2", Status: graphstore.IngestRunStatusFailed},
			{ID: "running-1", Status: graphstore.IngestRunStatusRunning},
		},
	}
	result, err := New(nil, nil, nil, store).Health(context.Background(), 1)
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if result.FailedCount != 2 {
		t.Fatalf("Health().FailedCount = %d, want 2", result.FailedCount)
	}
	if len(result.FailedRuns) != 1 {
		t.Fatalf("len(Health().FailedRuns) = %d, want 1", len(result.FailedRuns))
	}
	if result.RunningCount != 1 {
		t.Fatalf("Health().RunningCount = %d, want 1", result.RunningCount)
	}
	if result.Status != "degraded" {
		t.Fatalf("Health().Status = %q, want degraded", result.Status)
	}
}

func TestHealthEmitsTelemetry(t *testing.T) {
	store := &stubRunStore{
		runs: []graphstore.IngestRun{
			{ID: "failed-1", Status: graphstore.IngestRunStatusFailed},
			{ID: "running-1", Status: graphstore.IngestRunStatusRunning},
		},
	}
	stderr := captureGraphIngestStderr(t, func() {
		result, err := New(nil, nil, nil, store).Health(context.Background(), 1)
		if err != nil {
			t.Fatalf("Health() error = %v", err)
		}
		if result.Status != "degraded" {
			t.Fatalf("Health().Status = %q, want degraded", result.Status)
		}
	})

	payload := graphIngestTelemetryPayload(t, stderr, "graph.ingest_health")
	for key, want := range map[string]any{
		"kind":          "span_end",
		"name":          "graph.ingest_health",
		"status":        "completed",
		"limit":         float64(1),
		"health_status": "degraded",
		"failed_count":  float64(1),
		"running_count": float64(1),
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if _, ok := payload["duration_ms"].(float64); !ok {
		t.Fatalf("telemetry duration_ms = %#v, want number; payload=%#v", payload["duration_ms"], payload)
	}
}

func TestListRunsFailedCountHonorsRuntimeIDsFilter(t *testing.T) {
	store := &stubRunStore{
		runs: []graphstore.IngestRun{
			{ID: "runtime-a-failed", RuntimeID: "runtime-a", Status: graphstore.IngestRunStatusFailed},
			{ID: "runtime-b-failed", RuntimeID: "runtime-b", Status: graphstore.IngestRunStatusFailed},
			{ID: "runtime-c-failed", RuntimeID: "runtime-c", Status: graphstore.IngestRunStatusFailed},
			{ID: "runtime-a-completed", RuntimeID: "runtime-a", Status: graphstore.IngestRunStatusCompleted},
		},
	}
	result, err := New(nil, nil, nil, store).ListRuns(context.Background(), graphstore.IngestRunFilter{
		RuntimeIDs: []string{"runtime-a", "runtime-b"},
		Limit:      10,
	})
	if err != nil {
		t.Fatalf("ListRuns() error = %v", err)
	}
	if result.FailedCount != 2 {
		t.Fatalf("ListRuns().FailedCount = %d, want 2 scoped to runtime_ids", result.FailedCount)
	}
	if len(result.Runs) != 3 {
		t.Fatalf("len(ListRuns().Runs) = %d, want 3 scoped runs", len(result.Runs))
	}
}

func TestListRunsTelemetryRecordsInvalidRequest(t *testing.T) {
	stderr := captureGraphIngestStderr(t, func() {
		_, err := New(nil, nil, nil, &stubRunStore{}).ListRuns(context.Background(), graphstore.IngestRunFilter{Status: "bogus"})
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ListRuns() error = %v, want ErrInvalidRequest", err)
		}
	})

	payload := graphIngestTelemetryPayload(t, stderr, "graph.ingest_list_runs")
	if got := payload["status"]; got != "failed" {
		t.Fatalf("telemetry status = %#v, want failed; payload=%#v", got, payload)
	}
	if got := payload["error_kind"]; got != "invalid_request" {
		t.Fatalf("telemetry error_kind = %#v, want invalid_request; payload=%#v", got, payload)
	}
	if strings.Contains(stderr, "bogus") {
		t.Fatalf("ListRuns telemetry leaked raw invalid status value: %s", stderr)
	}
}

func TestHealthUsesLatestRunPerRuntime(t *testing.T) {
	store := &stubRunStore{
		runs: []graphstore.IngestRun{
			{
				ID:        "old-failed",
				RuntimeID: "runtime-a",
				Status:    graphstore.IngestRunStatusFailed,
				StartedAt: "2026-05-12T10:00:00Z",
			},
			{
				ID:        "new-completed",
				RuntimeID: "runtime-a",
				Status:    graphstore.IngestRunStatusCompleted,
				StartedAt: "2026-05-12T11:00:00Z",
			},
			{
				ID:        "latest-running",
				RuntimeID: "runtime-b",
				Status:    graphstore.IngestRunStatusRunning,
				StartedAt: "2026-05-12T12:00:00Z",
			},
		},
	}
	result, err := New(nil, nil, nil, store).Health(context.Background(), 10)
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if result.FailedCount != 0 {
		t.Fatalf("Health().FailedCount = %d, want 0", result.FailedCount)
	}
	if result.RunningCount != 1 {
		t.Fatalf("Health().RunningCount = %d, want 1", result.RunningCount)
	}
	if result.Status != "ready" {
		t.Fatalf("Health().Status = %q, want ready", result.Status)
	}
}

func TestPutTerminalIngestRunIgnoresParentCancellation(t *testing.T) {
	parentCtx, cancel := context.WithCancel(context.Background())
	cancel()
	store := &stubRunStore{
		putFunc: func(ctx context.Context, _ graphstore.IngestRun) error {
			if err := ctx.Err(); err != nil {
				t.Fatalf("PutIngestRun context error = %v, want nil", err)
			}
			return nil
		},
	}
	run := graphstore.IngestRun{ID: "run-1", Status: graphstore.IngestRunStatusFailed}
	if err := New(nil, nil, nil, nil).putTerminalIngestRun(parentCtx, store, run); err != nil {
		t.Fatalf("putTerminalIngestRun() error = %v", err)
	}
	if len(store.putRuns) != 1 {
		t.Fatalf("PutIngestRun calls = %d, want 1", len(store.putRuns))
	}
	if got := store.putRuns[0].Status; got != graphstore.IngestRunStatusFailed {
		t.Fatalf("persisted status = %q, want failed", got)
	}
}

func TestFinishRunClassifiesErrorsWithoutRawSecret(t *testing.T) {
	run := graphstore.IngestRun{ID: "run-1", Status: graphstore.IngestRunStatusRunning}
	finished := finishRun(run, nil, graphstore.IngestRunStatusFailed, errors.New("provider failed credential=fake-sensitive-value"))
	if finished.Error != "ingest_failed" {
		t.Fatalf("finishRun error = %q, want ingest_failed", finished.Error)
	}
	if strings.Contains(finished.Error, "fake-sensitive-value") || strings.Contains(finished.Error, "credential=") {
		t.Fatalf("finishRun leaked raw error: %q", finished.Error)
	}
}

func TestFinishRunClassifiesRateLimitsWithoutRawProviderError(t *testing.T) {
	tests := map[string]error{
		"source error": sourcecdk.WrapSourceError(
			sourcecdk.ErrorKindRateLimited,
			"example",
			"asset",
			errors.New("provider throttled credential=fake-sensitive-value"),
		),
		"http status": fmt.Errorf(
			"provider request failed: %w",
			&sourcecdk.HTTPStatusError{Code: 429, Message: "credential=fake-sensitive-value"},
		),
	}

	for name, runErr := range tests {
		t.Run(name, func(t *testing.T) {
			finished := finishRun(
				graphstore.IngestRun{ID: "run-1", Status: graphstore.IngestRunStatusRunning},
				nil,
				graphstore.IngestRunStatusFailed,
				runErr,
			)
			if finished.Error != "rate_limited" {
				t.Fatalf("finishRun error = %q, want rate_limited", finished.Error)
			}
			if strings.Contains(finished.Error, "fake-sensitive-value") || strings.Contains(finished.Error, "credential=") {
				t.Fatalf("finishRun leaked raw error: %q", finished.Error)
			}
		})
	}
}

func TestFinishRunPreservesCheckpointTerminalState(t *testing.T) {
	result := &IngestResult{
		CheckpointID:        "checkpoint-1",
		CheckpointCursor:    "page-2",
		CheckpointPersisted: true,
		CheckpointComplete:  false,
	}
	finished := finishRun(graphstore.IngestRun{ID: "run-1"}, result, graphstore.IngestRunStatusCompleted, nil)
	if finished.CheckpointID != result.CheckpointID || finished.CheckpointCursor != result.CheckpointCursor || finished.CheckpointComplete {
		t.Fatalf("finishRun checkpoint = %#v, want persisted partial checkpoint", finished)
	}
	result.CheckpointCursor = ""
	result.CheckpointComplete = true
	completed := finishRun(graphstore.IngestRun{ID: "run-2"}, result, graphstore.IngestRunStatusCompleted, nil)
	if completed.CheckpointCursor != "" || !completed.CheckpointComplete {
		t.Fatalf("finishRun checkpoint = %#v, want complete terminal checkpoint", completed)
	}
}

func TestGetRunRejectsEmptyID(t *testing.T) {
	_, err := New(nil, nil, nil, &stubRunStore{}).GetRun(context.Background(), " ")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetRun() error = %v, want ErrInvalidRequest", err)
	}
}

func TestListResultJSONUsesStableKeys(t *testing.T) {
	payload, err := json.Marshal(ListResult{
		Runs:        []graphstore.IngestRun{{ID: "run-1"}},
		FailedCount: 1,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(payload), "Runs") || strings.Contains(string(payload), "FailedCount") {
		t.Fatalf("ListResult JSON used Go field names: %s", payload)
	}
	if !strings.Contains(string(payload), `"runs"`) || !strings.Contains(string(payload), `"failed_count"`) {
		t.Fatalf("ListResult JSON missing stable keys: %s", payload)
	}
}

func captureGraphIngestStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stderr: %v", err)
	}
	os.Stderr = writer
	defer func() {
		os.Stderr = oldStderr
	}()
	fn()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := telemetry.FlushWideEvents(ctx); err != nil {
		t.Fatalf("flush telemetry: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(payload)
}

func graphIngestTelemetryPayload(t *testing.T, stderr string, name string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		payload := map[string]any{}
		if err := json.Unmarshal([]byte(lines[i]), &payload); err != nil {
			t.Fatalf("unmarshal telemetry payload %q: %v", lines[i], err)
		}
		if payload["kind"] == "span_end" && payload["name"] == name {
			return payload
		}
	}
	t.Fatalf("telemetry span_end %q not found in stderr: %s", name, stderr)
	return nil
}

// testProjectedLinkSet builds a complete desired outgoing associated_with
// link set for one owner of the writer tenant's vulnview source, matching
// what the vulnview.finding C9 projector emits.
func testProjectedLinkSet(runtimeID, ownerURN string, observation map[string]string, otherURNs ...string) *ports.ProjectedLinkSet {
	const tenantID, sourceID, relation = "writer", "vulnview", "associated_with"
	links := make([]*ports.ProjectedLink, 0, len(otherURNs))
	for _, other := range otherURNs {
		links = append(links, &ports.ProjectedLink{
			TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID,
			FromURN: ownerURN, ToURN: other, Relation: relation,
		})
	}
	return &ports.ProjectedLinkSet{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID,
		OwnerURN: ownerURN, Relation: relation, Outgoing: true,
		Links: links, Observation: observation,
	}
}

func noopProjectRecords(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, nil
}

// A link set is authoritative for its owner/relation/direction scope: plain
// links the same page emits for that exact scope must never reach the
// ordinary link upsert path, links outside that scope are unaffected, and
// the set itself is applied only after every entity in the page is upserted.
func TestProjectResponseCoalescedLinkSetAppliesAfterEntitiesAndExcludesCoveredLinks(t *testing.T) {
	store := &recordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	owner := "urn:cerebro:writer:aws_role:principal"
	consumerA := "urn:cerebro:writer:k8s_service_account:ns/a"
	consumerB := "urn:cerebro:writer:k8s_service_account:ns/b"
	uncoveredTarget := "urn:cerebro:writer:external_asset:other"

	set := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T10:00:00Z"}, consumerA, consumerB)
	coveredPlainLink := &ports.ProjectedLink{
		TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		FromURN: owner, ToURN: consumerA, Relation: "associated_with",
	}
	uncoveredPlainLink := &ports.ProjectedLink{
		TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		FromURN: owner, ToURN: uncoveredTarget, Relation: "has_evidence",
	}
	projector := linkSetProjector{
		recordProjectorFunc: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return []*ports.ProjectedEntity{{URN: owner, TenantID: "writer", SourceID: "vulnview", EntityType: "aws_role"}},
				[]*ports.ProjectedLink{coveredPlainLink, uncoveredPlainLink}, nil
		},
		linkSets: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
			return []*ports.ProjectedLinkSet{set}, nil
		},
	}
	result, err := service.projectResponseCoalesced(context.Background(), sourceRequest{SourceID: "vulnview", RuntimeID: "writer-vulnview", TenantID: "writer"}, &cerebrov1.ReadSourceResponse{
		Events: []*cerebrov1.EventEnvelope{{Id: "event-1", SourceId: "vulnview"}},
	}, projector, nil)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if store.linkSetCalls != 1 {
		t.Fatalf("ReplaceProjectedLinkSets called %d times, want 1", store.linkSetCalls)
	}
	stored := store.linkSetLinks[projectedLinkSetKey(set)]
	if len(stored) != 2 {
		t.Fatalf("stored link-set links = %d, want 2: %#v", len(stored), stored)
	}
	coveredKey := coveredPlainLink.FromURN + "|" + coveredPlainLink.Relation + "|" + coveredPlainLink.ToURN
	if _, ok := store.links[coveredKey]; ok {
		t.Fatalf("covered plain link reached the plain upsert path: %#v", store.links)
	}
	uncoveredKey := uncoveredPlainLink.FromURN + "|" + uncoveredPlainLink.Relation + "|" + uncoveredPlainLink.ToURN
	if _, ok := store.links[uncoveredKey]; !ok {
		t.Fatalf("uncovered plain link did not reach the plain upsert path: %#v", store.links)
	}
	if result.LinksProjected != 3 {
		t.Fatalf("LinksProjected = %d, want 3 (1 uncovered plain link + 2 from the applied set)", result.LinksProjected)
	}
	firstLinkSet, lastEntity := -1, -1
	for index, call := range store.callOrder {
		switch call {
		case "linkset":
			if firstLinkSet == -1 {
				firstLinkSet = index
			}
		case "entity":
			lastEntity = index
		}
	}
	if firstLinkSet == -1 || lastEntity == -1 || firstLinkSet < lastEntity {
		t.Fatalf("call order = %v, want every entity upsert before the link set is applied", store.callOrder)
	}
}

// {A,B} -> {A} must retract only B; A, asserted again by the merge path,
// survives untouched.
func TestProjectResponseCoalescedLinkSetRemovesOnlyDroppedLink(t *testing.T) {
	store := &recordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	owner := "urn:cerebro:writer:aws_role:principal"
	linkA := "urn:cerebro:writer:k8s_service_account:ns/a"
	linkB := "urn:cerebro:writer:k8s_service_account:ns/b"
	request := sourceRequest{SourceID: "vulnview", RuntimeID: "writer-vulnview", TenantID: "writer"}

	initial := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T10:00:00Z"}, linkA, linkB)
	projector := linkSetProjector{
		recordProjectorFunc: noopProjectRecords,
		linkSets: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
			return []*ports.ProjectedLinkSet{initial}, nil
		},
	}
	if _, err := service.projectResponseCoalesced(context.Background(), request, &cerebrov1.ReadSourceResponse{
		Events: []*cerebrov1.EventEnvelope{{Id: "event-1", SourceId: "vulnview"}},
	}, projector, nil); err != nil {
		t.Fatalf("projectResponseCoalesced(initial) error = %v", err)
	}
	key := projectedLinkSetKey(initial)
	if got := len(store.linkSetLinks[key]); got != 2 {
		t.Fatalf("after initial set, stored links = %d, want 2", got)
	}

	narrowed := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T10:05:00Z"}, linkA)
	projector.linkSets = func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
		return []*ports.ProjectedLinkSet{narrowed}, nil
	}
	if _, err := service.projectResponseCoalesced(context.Background(), request, &cerebrov1.ReadSourceResponse{
		Events: []*cerebrov1.EventEnvelope{{Id: "event-2", SourceId: "vulnview"}},
	}, projector, nil); err != nil {
		t.Fatalf("projectResponseCoalesced(narrowed) error = %v", err)
	}
	stored := store.linkSetLinks[key]
	if _, ok := stored[linkB]; ok {
		t.Fatalf("link B survived narrowing the set to {A}: %#v", stored)
	}
	if _, ok := stored[linkA]; !ok {
		t.Fatalf("link A was incorrectly removed: %#v", stored)
	}
	if len(stored) != 1 {
		t.Fatalf("stored links = %d, want 1 (only A)", len(stored))
	}
}

// Within one page, two events disagree about the same owner/relation/
// direction scope: the older observation's attempt to retract everything to
// empty must lose to the newer observation that keeps the links, and only
// the coalesced winner ever reaches the store.
func TestProjectResponseCoalescedLinkSetSamePageOlderObservationCannotRetract(t *testing.T) {
	store := &recordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	owner := "urn:cerebro:writer:aws_role:principal"
	linkA := "urn:cerebro:writer:k8s_service_account:ns/a"
	linkB := "urn:cerebro:writer:k8s_service_account:ns/b"

	newest := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T10:00:00Z"}, linkA, linkB)
	olderRetractAttempt := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T09:00:00Z"})
	eventSets := map[string]*ports.ProjectedLinkSet{"event-old": olderRetractAttempt, "event-new": newest}
	projector := linkSetProjector{
		recordProjectorFunc: noopProjectRecords,
		linkSets: func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
			return []*ports.ProjectedLinkSet{eventSets[event.GetId()]}, nil
		},
	}
	events := []*cerebrov1.EventEnvelope{{Id: "event-old", SourceId: "vulnview"}, {Id: "event-new", SourceId: "vulnview"}}
	if _, err := service.projectResponseCoalesced(context.Background(), sourceRequest{SourceID: "vulnview", RuntimeID: "writer-vulnview", TenantID: "writer"}, &cerebrov1.ReadSourceResponse{Events: events}, projector, nil); err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if store.linkSetSetsReceived != 1 {
		t.Fatalf("sets received by the store = %d, want 1 (coalesced within the page before reaching the store)", store.linkSetSetsReceived)
	}
	stored := store.linkSetLinks[projectedLinkSetKey(newest)]
	if len(stored) != 2 {
		t.Fatalf("an older same-page observation retracted links: stored = %#v, want {A, B}", stored)
	}
}

// Within one page, the older observation tries to restore a link the newer,
// authoritative-empty observation already cleared; coalescing must still
// keep the empty winner regardless of event iteration order.
func TestProjectResponseCoalescedLinkSetSamePageOlderObservationCannotRestore(t *testing.T) {
	store := &recordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	owner := "urn:cerebro:writer:aws_role:principal"
	linkA := "urn:cerebro:writer:k8s_service_account:ns/a"

	newestEmpty := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T10:00:00Z"})
	olderRestoreAttempt := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T09:00:00Z"}, linkA)
	eventSets := map[string]*ports.ProjectedLinkSet{"event-new": newestEmpty, "event-old": olderRestoreAttempt}
	projector := linkSetProjector{
		recordProjectorFunc: noopProjectRecords,
		linkSets: func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
			return []*ports.ProjectedLinkSet{eventSets[event.GetId()]}, nil
		},
	}
	// The newest, empty observation is processed first and the stale restore
	// attempt second, so a coalescing bug that let the last-processed event
	// win would incorrectly restore link A.
	events := []*cerebrov1.EventEnvelope{{Id: "event-new", SourceId: "vulnview"}, {Id: "event-old", SourceId: "vulnview"}}
	if _, err := service.projectResponseCoalesced(context.Background(), sourceRequest{SourceID: "vulnview", RuntimeID: "writer-vulnview", TenantID: "writer"}, &cerebrov1.ReadSourceResponse{Events: events}, projector, nil); err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if store.linkSetSetsReceived != 1 {
		t.Fatalf("sets received by the store = %d, want 1 (coalesced within the page before reaching the store)", store.linkSetSetsReceived)
	}
	stored := store.linkSetLinks[projectedLinkSetKey(newestEmpty)]
	if len(stored) != 0 {
		t.Fatalf("an older same-page observation restored link A: %#v", stored)
	}
}

// TestProjectResponseCoalescedLinkSetSamePageEndpointWinnerIsOrderIndependent
// pins R06 at the page-coalescing level: when two same-page observations
// disagree about one owner/relation/direction scope, coalescing keeps the
// whole winning set (including its Endpoints) regardless of event
// iteration order, so the loser's Endpoints never reach the store.
func TestProjectResponseCoalescedLinkSetSamePageEndpointWinnerIsOrderIndependent(t *testing.T) {
	owner := "urn:cerebro:writer:aws_role:principal"
	consumerA := "urn:cerebro:writer:k8s_service_account:ns/a"
	consumerB := "urn:cerebro:writer:k8s_service_account:ns/b"
	endpointFor := func(urn string) *ports.ProjectedEntity {
		return &ports.ProjectedEntity{URN: urn, TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview", EntityType: "kubernetes.service_account", Label: urn, CreateOnly: true}
	}
	newest := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T10:00:00Z"}, consumerA)
	newest.Endpoints = []*ports.ProjectedEntity{endpointFor(consumerA)}
	olderWithB := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T09:00:00Z"}, consumerB)
	olderWithB.Endpoints = []*ports.ProjectedEntity{endpointFor(consumerB)}
	eventSets := map[string]*ports.ProjectedLinkSet{"event-new": newest, "event-old": olderWithB}

	for _, order := range []struct {
		name   string
		events []*cerebrov1.EventEnvelope
	}{
		{"new-then-old", []*cerebrov1.EventEnvelope{{Id: "event-new", SourceId: "vulnview"}, {Id: "event-old", SourceId: "vulnview"}}},
		{"old-then-new", []*cerebrov1.EventEnvelope{{Id: "event-old", SourceId: "vulnview"}, {Id: "event-new", SourceId: "vulnview"}}},
	} {
		t.Run(order.name, func(t *testing.T) {
			store := &recordingProjectionGraphStore{}
			service := &Service{graphStore: store}
			projector := linkSetProjector{
				recordProjectorFunc: noopProjectRecords,
				linkSets: func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
					return []*ports.ProjectedLinkSet{eventSets[event.GetId()]}, nil
				},
			}
			if _, err := service.projectResponseCoalesced(context.Background(), sourceRequest{SourceID: "vulnview", RuntimeID: "writer-vulnview", TenantID: "writer"}, &cerebrov1.ReadSourceResponse{Events: order.events}, projector, nil); err != nil {
				t.Fatalf("projectResponseCoalesced() error = %v", err)
			}
			if store.linkSetSetsReceived != 1 {
				t.Fatalf("sets received by the store = %d, want 1 (coalesced within the page before reaching the store)", store.linkSetSetsReceived)
			}
			stored := store.linkSetLinks[projectedLinkSetKey(newest)]
			if len(stored) != 1 || stored[consumerA] == nil {
				t.Fatalf("stored links = %#v, want only the newest observation's consumerA", stored)
			}
			if _, exists := store.entities[consumerA]; !exists {
				t.Fatalf("winning observation's endpoint A was never materialized: %#v", store.entities)
			}
			if _, exists := store.entities[consumerB]; exists {
				t.Fatalf("losing observation's endpoint B was materialized: %#v", store.entities)
			}
		})
	}
}

// A stale observation delivered in a later, separate page must still be
// unable to retract or restore anything: the store's persisted guard (not
// just within-page coalescing) rejects it.
func TestProjectResponseCoalescedLinkSetGuardsStaleObservationAcrossPages(t *testing.T) {
	store := &recordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	owner := "urn:cerebro:writer:aws_role:principal"
	linkA := "urn:cerebro:writer:k8s_service_account:ns/a"
	request := sourceRequest{SourceID: "vulnview", RuntimeID: "writer-vulnview", TenantID: "writer"}

	current := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T10:00:00Z"}, linkA)
	projector := linkSetProjector{
		recordProjectorFunc: noopProjectRecords,
		linkSets: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
			return []*ports.ProjectedLinkSet{current}, nil
		},
	}
	if _, err := service.projectResponseCoalesced(context.Background(), request, &cerebrov1.ReadSourceResponse{
		Events: []*cerebrov1.EventEnvelope{{Id: "event-1", SourceId: "vulnview"}},
	}, projector, nil); err != nil {
		t.Fatalf("projectResponseCoalesced(current) error = %v", err)
	}

	stale := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T09:00:00Z"})
	projector.linkSets = func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
		return []*ports.ProjectedLinkSet{stale}, nil
	}
	if _, err := service.projectResponseCoalesced(context.Background(), request, &cerebrov1.ReadSourceResponse{
		Events: []*cerebrov1.EventEnvelope{{Id: "event-2", SourceId: "vulnview"}},
	}, projector, nil); err != nil {
		t.Fatalf("projectResponseCoalesced(stale) error = %v", err)
	}
	stored := store.linkSetLinks[projectedLinkSetKey(current)]
	if len(stored) != 1 {
		t.Fatalf("a stale page retracted link A: %#v", stored)
	}
	if _, ok := stored[linkA]; !ok {
		t.Fatalf("link A missing after the stale page: %#v", stored)
	}
}

// Applying a set for one tenant/source/runtime must never touch another
// tenant/source/runtime's assertions on the exact same owner and relation.
func TestProjectResponseCoalescedLinkSetLeavesOtherRuntimeUntouched(t *testing.T) {
	store := &recordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	owner := "urn:cerebro:writer:aws_role:principal"
	otherRuntimeLink := "urn:cerebro:writer:k8s_service_account:other-cluster/a"
	ourLink := "urn:cerebro:writer:k8s_service_account:our-cluster/a"

	otherRuntimeSet := testProjectedLinkSet("other-runtime", owner, map[string]string{"at": "2026-11-02T10:00:00Z"}, otherRuntimeLink)
	ourSet := testProjectedLinkSet("our-runtime", owner, map[string]string{"at": "2026-11-02T10:00:00Z"}, ourLink)
	projector := linkSetProjector{recordProjectorFunc: noopProjectRecords}

	projector.linkSets = func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
		return []*ports.ProjectedLinkSet{otherRuntimeSet}, nil
	}
	if _, err := service.projectResponseCoalesced(context.Background(), sourceRequest{SourceID: "vulnview", RuntimeID: "other-runtime", TenantID: "writer"}, &cerebrov1.ReadSourceResponse{
		Events: []*cerebrov1.EventEnvelope{{Id: "event-1", SourceId: "vulnview"}},
	}, projector, nil); err != nil {
		t.Fatalf("projectResponseCoalesced(other runtime) error = %v", err)
	}

	narrowingOtherRuntime := testProjectedLinkSet("our-runtime", owner, map[string]string{"at": "2026-11-02T10:05:00Z"}, ourLink)
	projector.linkSets = func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
		return []*ports.ProjectedLinkSet{narrowingOtherRuntime}, nil
	}
	if _, err := service.projectResponseCoalesced(context.Background(), sourceRequest{SourceID: "vulnview", RuntimeID: "our-runtime", TenantID: "writer"}, &cerebrov1.ReadSourceResponse{
		Events: []*cerebrov1.EventEnvelope{{Id: "event-2", SourceId: "vulnview"}},
	}, projector, nil); err != nil {
		t.Fatalf("projectResponseCoalesced(our runtime) error = %v", err)
	}

	otherStored := store.linkSetLinks[projectedLinkSetKey(otherRuntimeSet)]
	if len(otherStored) != 1 {
		t.Fatalf("other runtime's assertion was touched: %#v", otherStored)
	}
	if _, ok := otherStored[otherRuntimeLink]; !ok {
		t.Fatalf("other runtime's link is missing: %#v", otherStored)
	}
	ourStored := store.linkSetLinks[projectedLinkSetKey(ourSet)]
	if len(ourStored) != 1 {
		t.Fatalf("our runtime's link set = %#v, want exactly {ourLink}", ourStored)
	}
}

// An authoritative empty set clears every previously asserted link for its
// owner/relation/direction/runtime scope.
func TestProjectResponseCoalescedLinkSetAuthoritativeEmptySetClears(t *testing.T) {
	store := &recordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	owner := "urn:cerebro:writer:aws_role:principal"
	linkA := "urn:cerebro:writer:k8s_service_account:ns/a"
	linkB := "urn:cerebro:writer:k8s_service_account:ns/b"
	request := sourceRequest{SourceID: "vulnview", RuntimeID: "writer-vulnview", TenantID: "writer"}

	initial := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T10:00:00Z"}, linkA, linkB)
	projector := linkSetProjector{
		recordProjectorFunc: noopProjectRecords,
		linkSets: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
			return []*ports.ProjectedLinkSet{initial}, nil
		},
	}
	if _, err := service.projectResponseCoalesced(context.Background(), request, &cerebrov1.ReadSourceResponse{
		Events: []*cerebrov1.EventEnvelope{{Id: "event-1", SourceId: "vulnview"}},
	}, projector, nil); err != nil {
		t.Fatalf("projectResponseCoalesced(initial) error = %v", err)
	}

	cleared := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T10:05:00Z"})
	projector.linkSets = func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
		return []*ports.ProjectedLinkSet{cleared}, nil
	}
	if _, err := service.projectResponseCoalesced(context.Background(), request, &cerebrov1.ReadSourceResponse{
		Events: []*cerebrov1.EventEnvelope{{Id: "event-2", SourceId: "vulnview"}},
	}, projector, nil); err != nil {
		t.Fatalf("projectResponseCoalesced(cleared) error = %v", err)
	}
	stored := store.linkSetLinks[projectedLinkSetKey(initial)]
	if len(stored) != 0 {
		t.Fatalf("authoritative empty set left links behind: %#v", stored)
	}
}

// When a page's projector never emits link sets, plain links flow through
// the ordinary upsert path untouched and the link-set store is never called.
func TestProjectResponseCoalescedLinkSetsAbsentLeavesLinksUntouched(t *testing.T) {
	store := &recordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	plainLink := &ports.ProjectedLink{
		TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		FromURN: "urn:cerebro:writer:aws_role:principal", ToURN: "urn:cerebro:writer:k8s_service_account:ns/a",
		Relation: "associated_with",
	}
	projector := recordProjectorFunc(func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return nil, []*ports.ProjectedLink{plainLink}, nil
	})
	if _, err := service.projectResponseCoalesced(context.Background(), sourceRequest{SourceID: "vulnview", RuntimeID: "writer-vulnview", TenantID: "writer"}, &cerebrov1.ReadSourceResponse{
		Events: []*cerebrov1.EventEnvelope{{Id: "event-1", SourceId: "vulnview"}},
	}, projector, nil); err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if store.linkSetCalls != 0 {
		t.Fatalf("ReplaceProjectedLinkSets called %d times, want 0 (no sets emitted)", store.linkSetCalls)
	}
	key := plainLink.FromURN + "|" + plainLink.Relation + "|" + plainLink.ToURN
	if _, ok := store.links[key]; !ok {
		t.Fatalf("plain link was not upserted when no link sets were emitted: %#v", store.links)
	}
}

// Contract G1 page coalescing: a CreateOnly stub must never contribute
// attributes, label, or ownership over an ordinary entity for the same
// URN within one page, regardless of which event arrives first. Before
// this fix mergeProjectedEntity blindly overwrote fields, so an ordinary
// principal projected earlier in the page could lose its label/source to
// a later VulnView endpoint stub (or vice versa).
func TestProjectResponseCoalescedEntityOrdinaryWinsOverCreateOnlyStubRegardlessOfOrder(t *testing.T) {
	owner := "urn:cerebro:writer:aws_role:principal"
	ordinary := &ports.ProjectedEntity{
		URN: owner, TenantID: "writer", SourceID: "aws", RuntimeID: "writer-aws",
		EntityType: "aws.role", Label: "arn:aws:iam::111:role/principal",
		Attributes: map[string]string{"account_id": "111"},
	}
	stub := &ports.ProjectedEntity{
		URN: owner, TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		EntityType: "aws.role", Label: owner, CreateOnly: true,
	}
	for _, order := range []struct {
		name     string
		entities []*ports.ProjectedEntity
	}{
		{"ordinary then stub", []*ports.ProjectedEntity{ordinary, stub}},
		{"stub then ordinary", []*ports.ProjectedEntity{stub, ordinary}},
	} {
		t.Run(order.name, func(t *testing.T) {
			store := &recordingProjectionGraphStore{}
			service := &Service{graphStore: store}
			entities := order.entities
			projector := recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
				index := 0
				if event.GetId() == "event-2" {
					index = 1
				}
				return []*ports.ProjectedEntity{entities[index]}, nil, nil
			})
			if _, err := service.projectResponseCoalesced(context.Background(), sourceRequest{SourceID: "vulnview", RuntimeID: "writer-vulnview", TenantID: "writer"}, &cerebrov1.ReadSourceResponse{
				Events: []*cerebrov1.EventEnvelope{{Id: "event-1"}, {Id: "event-2"}},
			}, projector, nil); err != nil {
				t.Fatalf("projectResponseCoalesced() error = %v", err)
			}
			got := store.entities[owner]
			if got == nil {
				t.Fatalf("entity %q was not upserted", owner)
			}
			if got.SourceID != "aws" || got.Label != ordinary.Label || got.Attributes["account_id"] != "111" || got.CreateOnly {
				t.Fatalf("stored entity = %#v, want the ordinary entity untouched by the stub", got)
			}
		})
	}
}

// Contract G1 entity merge: an accepted observation's RetractedAttributes
// keys absent from its own Attributes must be deleted from the coalesced
// attributes that reach the store, even when both observations arrive
// within the same page.
func TestProjectResponseCoalescedEntityAppliesRetractedAttributes(t *testing.T) {
	store := &recordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	urn := "urn:cerebro:writer:finding:f-1"
	first := &ports.ProjectedEntity{
		URN: urn, TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		EntityType: "finding",
		Attributes: map[string]string{"triage_state": "accepted", "triage_reason": "reviewed", "status": "open"},
	}
	second := &ports.ProjectedEntity{
		URN: urn, TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		EntityType:          "finding",
		Attributes:          map[string]string{"triage_state": "none", "status": "open"},
		RetractedAttributes: []string{"triage_reason"},
	}
	projector := recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		if event.GetId() == "event-1" {
			return []*ports.ProjectedEntity{first}, nil, nil
		}
		return []*ports.ProjectedEntity{second}, nil, nil
	})
	if _, err := service.projectResponseCoalesced(context.Background(), sourceRequest{SourceID: "vulnview", RuntimeID: "writer-vulnview", TenantID: "writer"}, &cerebrov1.ReadSourceResponse{
		Events: []*cerebrov1.EventEnvelope{{Id: "event-1"}, {Id: "event-2"}},
	}, projector, nil); err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	got := store.entities[urn]
	if got == nil {
		t.Fatalf("entity %q was not upserted", urn)
	}
	if _, present := got.Attributes["triage_reason"]; present {
		t.Fatalf("attributes = %#v, want triage_reason retracted", got.Attributes)
	}
	if got.Attributes["triage_state"] != "none" || got.Attributes["status"] != "open" {
		t.Fatalf("attributes = %#v, want triage_state=none and status preserved", got.Attributes)
	}
	if len(got.RetractedAttributes) != 1 || got.RetractedAttributes[0] != "triage_reason" {
		t.Fatalf("retracted attributes = %#v, want [triage_reason] forwarded to the store", got.RetractedAttributes)
	}
}

// F04 regression: v1 {A} establishes the scope in an earlier page. A later
// page then carries, within the SAME page, both an Incomplete observation
// (newest) and a stale replay of v2 {B} (older) for the same owner/
// relation/direction/runtime scope. Graphingest's page coalescing must
// keep only the newest (Incomplete) observation regardless of the two
// events' order within the page, so the store only ever sees it — never
// the stale {B} replay — and {A} must survive untouched.
func TestProjectResponseCoalescedLinkSetIncompleteSurvivesSamePageReplayRegardlessOfOrder(t *testing.T) {
	owner := "urn:cerebro:writer:aws_role:principal"
	linkA := "urn:cerebro:writer:k8s_service_account:ns/a"
	linkB := "urn:cerebro:writer:k8s_service_account:ns/b"
	request := sourceRequest{SourceID: "vulnview", RuntimeID: "writer-vulnview", TenantID: "writer"}

	v1 := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-01T10:00:00Z"}, linkA)
	v2Replay := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T10:00:00Z"}, linkB)
	v3Incomplete := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-03T10:00:00Z"})
	v3Incomplete.Incomplete = true

	for _, order := range []struct {
		name   string
		events []*cerebrov1.EventEnvelope
		sets   map[string]*ports.ProjectedLinkSet
	}{
		{"v2 then incomplete v3", []*cerebrov1.EventEnvelope{{Id: "event-v2"}, {Id: "event-v3"}}, map[string]*ports.ProjectedLinkSet{"event-v2": v2Replay, "event-v3": v3Incomplete}},
		{"incomplete v3 then v2", []*cerebrov1.EventEnvelope{{Id: "event-v3"}, {Id: "event-v2"}}, map[string]*ports.ProjectedLinkSet{"event-v2": v2Replay, "event-v3": v3Incomplete}},
	} {
		t.Run(order.name, func(t *testing.T) {
			store := &recordingProjectionGraphStore{}
			service := &Service{graphStore: store}
			// Establish {A} in an earlier page.
			initial := linkSetProjector{
				recordProjectorFunc: noopProjectRecords,
				linkSets: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
					return []*ports.ProjectedLinkSet{v1}, nil
				},
			}
			if _, err := service.projectResponseCoalesced(context.Background(), request, &cerebrov1.ReadSourceResponse{
				Events: []*cerebrov1.EventEnvelope{{Id: "event-v1"}},
			}, initial, nil); err != nil {
				t.Fatalf("projectResponseCoalesced(v1) error = %v", err)
			}
			key := projectedLinkSetKey(v1)
			if got := len(store.linkSetLinks[key]); got != 1 {
				t.Fatalf("after v1, stored links = %d, want 1 ({A})", got)
			}

			// The later page carries both the stale v2 replay and the
			// newest Incomplete observation, in this subtest's order.
			sets := order.sets
			projector := linkSetProjector{
				recordProjectorFunc: noopProjectRecords,
				linkSets: func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
					return []*ports.ProjectedLinkSet{sets[event.GetId()]}, nil
				},
			}
			setsReceivedBefore := store.linkSetSetsReceived
			if _, err := service.projectResponseCoalesced(context.Background(), request, &cerebrov1.ReadSourceResponse{
				Events: order.events,
			}, projector, nil); err != nil {
				t.Fatalf("projectResponseCoalesced(page) error = %v", err)
			}
			if got := store.linkSetSetsReceived - setsReceivedBefore; got != 1 {
				t.Fatalf("sets received by the store this page = %d, want 1 (coalesced to the newest Incomplete observation)", got)
			}
			stored := store.linkSetLinks[key]
			if len(stored) != 1 || stored[linkA] == nil {
				t.Fatalf("after the same-page incomplete/stale-replay page (%s), stored links = %#v, want {A} to survive untouched", order.name, stored)
			}
			if _, ok := stored[linkB]; ok {
				t.Fatalf("stale replayed {B} reached the store (%s): %#v", order.name, stored)
			}
		})
	}
}

// unsupportedLinkSetGraphStore implements only the bare minimum of
// ports.ProjectionGraphStore — notably NOT ports.ProjectionLinkSetStore —
// so tests can prove a page that carries link sets fails closed against a
// store that cannot apply them, instead of silently dropping the covered
// plain links while reporting success.
type unsupportedLinkSetGraphStore struct {
	links map[string]*ports.ProjectedLink
}

func (s *unsupportedLinkSetGraphStore) Ping(context.Context) error { return nil }

func (s *unsupportedLinkSetGraphStore) UpsertProjectedEntity(context.Context, *ports.ProjectedEntity) error {
	return nil
}

func (s *unsupportedLinkSetGraphStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if s.links == nil {
		s.links = map[string]*ports.ProjectedLink{}
	}
	s.links[link.FromURN+"|"+link.Relation+"|"+link.ToURN] = link
	return nil
}

var _ ports.ProjectionGraphStore = (*unsupportedLinkSetGraphStore)(nil)

// Before this fix, projectResponseCoalesced's applyLinkSets silently
// returned nil when the graph store did not implement
// ports.ProjectionLinkSetStore, so the page's covered consumer links were
// permanently dropped (never applied as a set, and excluded from the
// plain link path by their own coverage) while the page still reported
// success.
func TestProjectResponseCoalescedFailsClosedWhenLinkSetStoreUnsupported(t *testing.T) {
	store := &unsupportedLinkSetGraphStore{}
	service := &Service{graphStore: store}
	owner := "urn:cerebro:writer:aws_role:principal"
	consumer := "urn:cerebro:writer:k8s_service_account:ns/a"
	set := testProjectedLinkSet("writer-vulnview", owner, map[string]string{"at": "2026-11-02T10:00:00Z"}, consumer)
	coveredPlainLink := &ports.ProjectedLink{
		TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		FromURN: owner, ToURN: consumer, Relation: "associated_with",
	}
	projector := linkSetProjector{
		recordProjectorFunc: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return []*ports.ProjectedEntity{{URN: owner, TenantID: "writer", SourceID: "vulnview", EntityType: "aws_role"}},
				[]*ports.ProjectedLink{coveredPlainLink}, nil
		},
		linkSets: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
			return []*ports.ProjectedLinkSet{set}, nil
		},
	}
	_, err := service.projectResponseCoalesced(context.Background(), sourceRequest{SourceID: "vulnview", RuntimeID: "writer-vulnview", TenantID: "writer"}, &cerebrov1.ReadSourceResponse{
		Events: []*cerebrov1.EventEnvelope{{Id: "event-1", SourceId: "vulnview"}},
	}, projector, nil)
	if !errors.Is(err, ports.ErrProjectionLinkSetStoreUnsupported) {
		t.Fatalf("projectResponseCoalesced() error = %v, want ports.ErrProjectionLinkSetStoreUnsupported", err)
	}
	coveredKey := coveredPlainLink.FromURN + "|" + coveredPlainLink.Relation + "|" + coveredPlainLink.ToURN
	if _, ok := store.links[coveredKey]; ok {
		t.Fatalf("covered plain link reached the plain upsert path despite the failure: %#v", store.links)
	}
}
