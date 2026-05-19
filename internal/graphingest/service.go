package graphingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/telemetry"
)

const (
	DefaultPageLimit         = 1
	MaxPageLimit             = 100
	DefaultStatusLimit       = 25
	MaxStatusLimit           = 500
	terminalRunUpdateTimeout = 15 * time.Second
)

var (
	ErrRuntimeUnavailable = errors.New("graph ingest runtime is unavailable")
	ErrRunNotFound        = errors.New("graph ingest run not found")
	ErrInvalidRequest     = errors.New("invalid graph ingest request")
)

type CountsStore interface {
	Counts(context.Context) (graphstore.Counts, error)
}

type CheckpointStore interface {
	GetIngestCheckpoint(context.Context, string) (graphstore.IngestCheckpoint, bool, error)
	PutIngestCheckpoint(context.Context, graphstore.IngestCheckpoint) error
}

type RunStore interface {
	PutIngestRun(context.Context, graphstore.IngestRun) error
	GetIngestRun(context.Context, string) (graphstore.IngestRun, bool, error)
	ListIngestRuns(context.Context, graphstore.IngestRunFilter) ([]graphstore.IngestRun, error)
}

type ConfigPreparer func(context.Context, string, map[string]string) (map[string]string, error)

type Service struct {
	sourceService *sourceops.Service
	runtimeStore  ports.SourceRuntimeStore
	projector     ports.SourceProjector
	graphStore    ports.GraphStore
	prepareConfig ConfigPreparer
}

type projectionRecordProjector interface {
	ProjectRecords(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)
}

type pageProjectionResult struct {
	EventsRead        uint32
	EntitiesProjected uint32
	LinksProjected    uint32
}

type RuntimeRequest struct {
	RuntimeID       string
	PageLimit       uint32
	CheckpointID    string
	ResetCheckpoint bool
	Trigger         string
}

type IngestResult struct {
	SourceID               string `json:"source_id"`
	TenantID               string `json:"tenant_id,omitempty"`
	PagesRead              uint32 `json:"pages_read"`
	EventsRead             uint32 `json:"events_read"`
	EntitiesProjected      uint32 `json:"entities_projected"`
	LinksProjected         uint32 `json:"links_projected"`
	GraphNodesBefore       int64  `json:"graph_nodes_before,omitempty"`
	GraphLinksBefore       int64  `json:"graph_links_before,omitempty"`
	GraphNodesAfter        int64  `json:"graph_nodes_after,omitempty"`
	GraphLinksAfter        int64  `json:"graph_links_after,omitempty"`
	NextCursor             string `json:"next_cursor,omitempty"`
	CheckpointID           string `json:"checkpoint_id,omitempty"`
	CheckpointCursor       string `json:"checkpoint_cursor,omitempty"`
	CheckpointResumed      bool   `json:"checkpoint_resumed,omitempty"`
	CheckpointPersisted    bool   `json:"checkpoint_persisted,omitempty"`
	CheckpointComplete     bool   `json:"checkpoint_complete,omitempty"`
	CheckpointAlreadyFresh bool   `json:"checkpoint_already_fresh,omitempty"`
}

type RunResult struct {
	Run    graphstore.IngestRun `json:"run"`
	Ingest *IngestResult        `json:"ingest,omitempty"`
}

type ListResult struct {
	Runs        []graphstore.IngestRun `json:"runs"`
	FailedCount uint32                 `json:"failed_count"`
}

type HealthResult struct {
	Status       string                 `json:"status"`
	CheckedAt    time.Time              `json:"checked_at"`
	FailedCount  uint32                 `json:"failed_count"`
	RunningCount uint32                 `json:"running_count"`
	FailedRuns   []graphstore.IngestRun `json:"failed_runs"`
}

func New(registry *sourcecdk.Registry, runtimeStore ports.SourceRuntimeStore, projector ports.SourceProjector, graphStore ports.GraphStore) *Service {
	return &Service{
		sourceService: sourceops.New(registry).WithInternalConfigAllowed(),
		runtimeStore:  runtimeStore,
		projector:     projector,
		graphStore:    graphStore,
	}
}

func (s *Service) WithConfigPreparer(prepare ConfigPreparer) *Service {
	if s == nil {
		return nil
	}
	s.prepareConfig = prepare
	return s
}

func (s *Service) RunRuntime(ctx context.Context, request RuntimeRequest) (result *RunResult, err error) {
	ctx, span := telemetry.Start(ctx, "graph.ingest_runtime", telemetry.Attrs(
		telemetry.Field{Key: "runtime_id", Value: strings.TrimSpace(request.RuntimeID)},
		telemetry.Field{Key: "page_limit", Value: request.PageLimit},
		telemetry.Field{Key: "checkpoint_id", Value: strings.TrimSpace(request.CheckpointID)},
		telemetry.Field{Key: "reset_checkpoint", Value: request.ResetCheckpoint},
		telemetry.Field{Key: "trigger", Value: strings.TrimSpace(request.Trigger)},
	))
	status := "failed"
	spanAttributes := telemetry.Attrs()
	defer func() {
		if result != nil {
			spanAttributes = graphIngestTelemetryAttributes(spanAttributes, result)
		}
		if err != nil {
			spanAttributes = spanAttributes.WithField(telemetry.Field{Key: "error", Value: err.Error()})
		}
		telemetry.End(span, status, spanAttributes)
	}()
	if s == nil || s.runtimeStore == nil || s.graphStore == nil || s.projector == nil {
		return nil, ErrRuntimeUnavailable
	}
	runStore, ok := s.graphStore.(RunStore)
	if !ok {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: runtime_id is required", ErrInvalidRequest)
	}
	pageLimit, err := normalizePageLimit(request.PageLimit)
	if err != nil {
		return nil, err
	}
	startedAt := time.Now().UTC()
	run := graphstore.IngestRun{
		ID:        ingestRunID(runtimeID, startedAt),
		RuntimeID: runtimeID,
		Status:    graphstore.IngestRunStatusRunning,
		Trigger:   ingestTrigger(request.Trigger),
		StartedAt: startedAt.Format(time.RFC3339Nano),
	}
	result = &RunResult{Run: run}
	if err := runStore.PutIngestRun(ctx, run); err != nil {
		return result, err
	}
	runtime, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID)
	if err != nil {
		return s.failRun(ctx, runStore, run, result, nil, err)
	}
	runtimeConfig, err := s.preparedConfig(ctx, runtime)
	if err != nil {
		run.SourceID = strings.TrimSpace(runtime.GetSourceId())
		run.TenantID = strings.TrimSpace(runtime.GetTenantId())
		return s.failRun(ctx, runStore, run, result, nil, err)
	}
	ingestRequest := sourceRequest{
		SourceID:          strings.TrimSpace(runtime.GetSourceId()),
		RuntimeID:         runtimeID,
		SourceConfig:      runtimeConfig,
		TenantID:          strings.TrimSpace(runtime.GetTenantId()),
		PageLimit:         pageLimit,
		CheckpointEnabled: true,
		CheckpointID:      runtimeCheckpointID(request, runtime, runtimeConfig),
		ResetCheckpoint:   request.ResetCheckpoint,
	}
	run.SourceID = ingestRequest.SourceID
	run.TenantID = ingestRequest.TenantID
	run.CheckpointID = ingestRequest.CheckpointID
	result.Run = run
	if err := runStore.PutIngestRun(ctx, run); err != nil {
		return result, err
	}
	ingest, err := s.ingestSource(ctx, ingestRequest)
	result.Ingest = ingest
	if err != nil {
		return s.failRun(ctx, runStore, run, result, ingest, err)
	}
	completed := finishRun(run, ingest, graphstore.IngestRunStatusCompleted, nil)
	result.Run = completed
	if err := s.putTerminalIngestRun(ctx, runStore, completed); err != nil {
		return result, err
	}
	status = "completed"
	return result, nil
}

func graphIngestTelemetryAttributes(attributes telemetry.Attributes, result *RunResult) telemetry.Attributes {
	if result == nil {
		return attributes
	}
	run := result.Run
	for _, field := range []telemetry.Field{
		{Key: "run_id", Value: run.ID},
		{Key: "runtime_id", Value: run.RuntimeID},
		{Key: "source_id", Value: run.SourceID},
		{Key: "tenant_id", Value: run.TenantID},
		{Key: "checkpoint_id", Value: run.CheckpointID},
		{Key: "pages_read", Value: run.PagesRead},
		{Key: "events_read", Value: run.EventsRead},
		{Key: "entities_projected", Value: run.EntitiesProjected},
		{Key: "links_projected", Value: run.LinksProjected},
		{Key: "checkpoint_persisted", Value: result.Ingest != nil && result.Ingest.CheckpointPersisted},
		{Key: "checkpoint_complete", Value: result.Ingest != nil && result.Ingest.CheckpointComplete},
		{Key: "checkpoint_already_fresh", Value: result.Ingest != nil && result.Ingest.CheckpointAlreadyFresh},
	} {
		attributes = attributes.WithField(field)
	}
	return attributes
}

func (s *Service) GetRun(ctx context.Context, id string) (graphstore.IngestRun, error) {
	runStore, err := s.runStore()
	if err != nil {
		return graphstore.IngestRun{}, err
	}
	runID := strings.TrimSpace(id)
	if runID == "" {
		return graphstore.IngestRun{}, fmt.Errorf("%w: run id is required", ErrInvalidRequest)
	}
	run, found, err := runStore.GetIngestRun(ctx, runID)
	if err != nil {
		return graphstore.IngestRun{}, err
	}
	if !found {
		return graphstore.IngestRun{}, ErrRunNotFound
	}
	return run, nil
}

func (s *Service) ListRuns(ctx context.Context, filter graphstore.IngestRunFilter) (*ListResult, error) {
	runStore, err := s.runStore()
	if err != nil {
		return nil, err
	}
	normalized, err := normalizeFilter(filter)
	if err != nil {
		return nil, err
	}
	runs, err := runStore.ListIngestRuns(ctx, normalized)
	if err != nil {
		return nil, err
	}
	failed, err := runStore.ListIngestRuns(ctx, graphstore.IngestRunFilter{
		RuntimeID: normalized.RuntimeID,
		Status:    graphstore.IngestRunStatusFailed,
		Limit:     MaxStatusLimit,
	})
	if err != nil {
		return nil, err
	}
	return &ListResult{Runs: runs, FailedCount: uint32(len(failed))}, nil
}

func (s *Service) Health(ctx context.Context, limit uint32) (*HealthResult, error) {
	runStore, err := s.runStore()
	if err != nil {
		return nil, err
	}
	normalizedLimit, err := normalizeStatusLimit(limit)
	if err != nil {
		return nil, err
	}
	recentRuns, err := runStore.ListIngestRuns(ctx, graphstore.IngestRunFilter{Limit: MaxStatusLimit})
	if err != nil {
		return nil, err
	}
	currentRuns := latestRunsByRuntime(recentRuns)
	failed := filterRunsByStatus(currentRuns, graphstore.IngestRunStatusFailed)
	running := filterRunsByStatus(currentRuns, graphstore.IngestRunStatusRunning)
	allFailed := failed
	if normalizedLimit > 0 && len(failed) > normalizedLimit {
		failed = failed[:normalizedLimit]
	}
	status := "ready"
	if len(allFailed) != 0 {
		status = "degraded"
	}
	return &HealthResult{
		Status:       status,
		CheckedAt:    time.Now().UTC(),
		FailedCount:  uint32(len(allFailed)),
		RunningCount: uint32(len(running)),
		FailedRuns:   failed,
	}, nil
}

func latestRunsByRuntime(runs []graphstore.IngestRun) []graphstore.IngestRun {
	latestByRuntime := map[string]graphstore.IngestRun{}
	for _, run := range runs {
		key := strings.TrimSpace(run.RuntimeID)
		if key == "" {
			key = strings.TrimSpace(run.ID)
		}
		if key == "" {
			continue
		}
		if current, ok := latestByRuntime[key]; !ok || ingestRunStartedAfter(run, current) {
			latestByRuntime[key] = run
		}
	}
	latest := make([]graphstore.IngestRun, 0, len(latestByRuntime))
	for _, run := range latestByRuntime {
		latest = append(latest, run)
	}
	sort.SliceStable(latest, func(i, j int) bool {
		if latest[i].StartedAt == latest[j].StartedAt {
			return latest[i].ID > latest[j].ID
		}
		return ingestRunStartedAfter(latest[i], latest[j])
	})
	return latest
}

func ingestRunStartedAfter(left graphstore.IngestRun, right graphstore.IngestRun) bool {
	leftStarted, leftErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(left.StartedAt))
	rightStarted, rightErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(right.StartedAt))
	if leftErr == nil && rightErr == nil && !leftStarted.Equal(rightStarted) {
		return leftStarted.After(rightStarted)
	}
	if leftErr == nil && rightErr != nil {
		return true
	}
	if leftErr != nil && rightErr == nil {
		return false
	}
	return left.ID > right.ID
}

func filterRunsByStatus(runs []graphstore.IngestRun, status string) []graphstore.IngestRun {
	filtered := make([]graphstore.IngestRun, 0, len(runs))
	for _, run := range runs {
		if run.Status == status {
			filtered = append(filtered, run)
		}
	}
	return filtered
}

func (s *Service) runStore() (RunStore, error) {
	if s == nil || s.graphStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	runStore, ok := s.graphStore.(RunStore)
	if !ok {
		return nil, ErrRuntimeUnavailable
	}
	return runStore, nil
}

func (s *Service) failRun(ctx context.Context, runStore RunStore, run graphstore.IngestRun, result *RunResult, ingest *IngestResult, runErr error) (*RunResult, error) {
	failed := finishRun(run, ingest, graphstore.IngestRunStatusFailed, runErr)
	result.Run = failed
	log.Printf("graph ingest runtime failed run_id=%q runtime_id=%q error=%v", failed.ID, failed.RuntimeID, runErr)
	return result, errors.Join(runErr, s.putTerminalIngestRun(ctx, runStore, failed))
}

func (s *Service) putTerminalIngestRun(ctx context.Context, runStore RunStore, run graphstore.IngestRun) error {
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), terminalRunUpdateTimeout)
	defer cancel()
	return runStore.PutIngestRun(persistCtx, run)
}

func (s *Service) preparedConfig(ctx context.Context, runtime *cerebrov1.SourceRuntime) (map[string]string, error) {
	config := sourceconfig.WithRuntimeTenant(runtime.GetConfig(), runtime.GetTenantId())
	config = sourceconfig.WithLegacyTenantlessAssumeRole(config, runtime.GetSourceId(), runtime.GetTenantId())
	if s.prepareConfig == nil {
		return config, nil
	}
	return s.prepareConfig(ctx, runtime.GetSourceId(), config)
}

type sourceRequest struct {
	SourceID          string
	RuntimeID         string
	SourceConfig      map[string]string
	TenantID          string
	PageLimit         uint32
	Cursor            *cerebrov1.SourceCursor
	CheckpointEnabled bool
	CheckpointID      string
	ResetCheckpoint   bool
}

func (s *Service) ingestSource(ctx context.Context, request sourceRequest) (*IngestResult, error) {
	result := &IngestResult{
		SourceID: strings.TrimSpace(request.SourceID),
		TenantID: strings.TrimSpace(request.TenantID),
	}
	cursor := request.Cursor
	checkpointStore, err := s.prepareCheckpoint(ctx, request, result, &cursor)
	if err != nil {
		return nil, err
	}
	if result.CheckpointAlreadyFresh {
		return result, nil
	}
	countsStore, hasCounts := s.graphStore.(CountsStore)
	if hasCounts {
		counts, err := countsStore.Counts(ctx)
		if err != nil {
			return nil, err
		}
		result.GraphNodesBefore = counts.Nodes
		result.GraphLinksBefore = counts.Relations
	}
	for i := uint32(0); i < request.PageLimit; i++ {
		response, err := s.sourceService.Read(ctx, &cerebrov1.ReadSourceRequest{
			SourceId: request.SourceID,
			Config:   request.SourceConfig,
			Cursor:   cursor,
		})
		if err != nil {
			return result, err
		}
		result.PagesRead++
		if recordProjector, ok := s.projector.(projectionRecordProjector); ok {
			projected, err := s.projectResponseCoalesced(ctx, request, response, recordProjector)
			result.EventsRead += projected.EventsRead
			result.EntitiesProjected += projected.EntitiesProjected
			result.LinksProjected += projected.LinksProjected
			if err != nil {
				return result, err
			}
		} else {
			for _, event := range response.GetEvents() {
				projected, err := s.projector.Project(ctx, ingestEvent(event, request.TenantID, request.RuntimeID))
				if err != nil {
					return result, fmt.Errorf("project source event %q: %w", event.GetId(), err)
				}
				result.EventsRead++
				result.EntitiesProjected += projected.EntitiesProjected
				result.LinksProjected += projected.LinksProjected
			}
		}
		cursor = response.GetNextCursor()
		if checkpointStore != nil {
			if err := persistCheckpoint(ctx, checkpointStore, request, result, response, cursor); err != nil {
				return result, err
			}
		}
		if cursor == nil {
			break
		}
	}
	if cursor != nil {
		result.NextCursor = strings.TrimSpace(cursor.GetOpaque())
	}
	if hasCounts {
		counts, err := countsStore.Counts(ctx)
		if err != nil {
			return result, err
		}
		result.GraphNodesAfter = counts.Nodes
		result.GraphLinksAfter = counts.Relations
	}
	return result, nil
}

func (s *Service) projectResponseCoalesced(ctx context.Context, request sourceRequest, response *cerebrov1.ReadSourceResponse, projector projectionRecordProjector) (pageProjectionResult, error) {
	graphStore, ok := s.graphStore.(ports.ProjectionGraphStore)
	if !ok {
		return pageProjectionResult{}, ErrRuntimeUnavailable
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	result := pageProjectionResult{}
	for _, event := range response.GetEvents() {
		ingested := ingestEvent(event, request.TenantID, request.RuntimeID)
		projectedEntities, projectedLinks, err := projector.ProjectRecords(ingested)
		if err != nil {
			return result, fmt.Errorf("project source event %q: %w", event.GetId(), err)
		}
		for _, entity := range projectedEntities {
			mergeProjectedEntity(entities, entity)
		}
		for _, link := range projectedLinks {
			mergeProjectedLink(links, link)
		}
		result.EventsRead++
	}
	entityKeys := sortedMapKeys(entities)
	for _, key := range entityKeys {
		if err := graphStore.UpsertProjectedEntity(ctx, entities[key]); err != nil {
			return result, fmt.Errorf("upsert coalesced projected entity %q: %w", key, err)
		}
		result.EntitiesProjected++
	}
	linkKeys := sortedMapKeys(links)
	for _, key := range linkKeys {
		if err := graphStore.UpsertProjectedLink(ctx, links[key]); err != nil {
			return result, fmt.Errorf("upsert coalesced projected link %q: %w", key, err)
		}
		result.LinksProjected++
	}
	return result, nil
}

func mergeProjectedEntity(entities map[string]*ports.ProjectedEntity, entity *ports.ProjectedEntity) {
	if entity == nil {
		return
	}
	urn := strings.TrimSpace(entity.URN)
	if urn == "" {
		return
	}
	existing, ok := entities[urn]
	if !ok {
		entities[urn] = cloneProjectedEntity(entity)
		return
	}
	if value := strings.TrimSpace(entity.TenantID); value != "" {
		existing.TenantID = value
	}
	if value := strings.TrimSpace(entity.SourceID); value != "" {
		existing.SourceID = value
	}
	if value := strings.TrimSpace(entity.RuntimeID); value != "" {
		existing.RuntimeID = value
	}
	if value := strings.TrimSpace(entity.EntityType); value != "" {
		existing.EntityType = value
	}
	if value := strings.TrimSpace(entity.Label); value != "" {
		existing.Label = value
	}
	existing.Attributes = mergeStringMap(existing.Attributes, entity.Attributes)
}

func mergeProjectedLink(links map[string]*ports.ProjectedLink, link *ports.ProjectedLink) {
	if link == nil {
		return
	}
	fromURN := strings.TrimSpace(link.FromURN)
	relation := strings.TrimSpace(link.Relation)
	toURN := strings.TrimSpace(link.ToURN)
	if fromURN == "" || relation == "" || toURN == "" {
		return
	}
	key := fromURN + "|" + relation + "|" + toURN
	existing, ok := links[key]
	if !ok {
		links[key] = cloneProjectedLink(link)
		return
	}
	if value := strings.TrimSpace(link.TenantID); value != "" {
		existing.TenantID = value
	}
	if value := strings.TrimSpace(link.SourceID); value != "" {
		existing.SourceID = value
	}
	if value := strings.TrimSpace(link.RuntimeID); value != "" {
		existing.RuntimeID = value
	}
	existing.Attributes = mergeStringMap(existing.Attributes, link.Attributes)
}

func mergeStringMap(dst map[string]string, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	incomingIsOlderObservation := projectedIncomingObservationIsOlder(dst, src)
	if !incomingIsOlderObservation && projectedIncomingObservationIsNewer(dst, src) {
		for key := range dst {
			if projectedAttributeCoupledToObservationTime(key) {
				delete(dst, key)
			}
		}
	}
	for key, value := range src {
		if incomingIsOlderObservation && projectedAttributeCoupledToObservationTime(key) {
			continue
		}
		dst[key] = mergeProjectedAttributeValue(key, dst[key], value)
	}
	return dst
}

func projectedIncomingObservationIsOlder(existing map[string]string, incoming map[string]string) bool {
	existingAt := strings.TrimSpace(existing["at"])
	incomingAt := strings.TrimSpace(incoming["at"])
	if existingAt == "" {
		return false
	}
	if incomingAt == "" {
		return true
	}
	existingT, errExisting := time.Parse(time.RFC3339, existingAt)
	incomingT, errIncoming := time.Parse(time.RFC3339, incomingAt)
	if errExisting != nil || errIncoming != nil {
		return false
	}
	return incomingT.Before(existingT)
}

func projectedIncomingObservationIsNewer(existing map[string]string, incoming map[string]string) bool {
	existingAt := strings.TrimSpace(existing["at"])
	incomingAt := strings.TrimSpace(incoming["at"])
	if existingAt == "" || incomingAt == "" {
		return false
	}
	existingT, errExisting := time.Parse(time.RFC3339, existingAt)
	incomingT, errIncoming := time.Parse(time.RFC3339, incomingAt)
	if errExisting != nil || errIncoming != nil {
		return false
	}
	return incomingT.After(existingT)
}

func projectedAttributeCoupledToObservationTime(key string) bool {
	switch key {
	case "action", "actor_type", "classification", "client_ip", "event_id", "event_type", "grant_type", "incident_status", "mitigation_status", "oauth_event_category", "outcome_reason", "outcome_result", "programmatic_access_type", "source_event_id", "source_runtime_id", "transaction_id", "transport_protocol_name":
		return true
	default:
		return false
	}
}

func mergeProjectedAttributeValue(key string, existing string, incoming string) string {
	if key != "at" {
		return incoming
	}
	if strings.TrimSpace(existing) == "" {
		return incoming
	}
	if strings.TrimSpace(incoming) == "" {
		return existing
	}
	existingT, errExisting := time.Parse(time.RFC3339, existing)
	incomingT, errIncoming := time.Parse(time.RFC3339, incoming)
	if errExisting != nil || errIncoming != nil {
		return incoming
	}
	if incomingT.Before(existingT) {
		return existing
	}
	return incoming
}

func cloneProjectedEntity(entity *ports.ProjectedEntity) *ports.ProjectedEntity {
	if entity == nil {
		return nil
	}
	clone := *entity
	clone.Attributes = cloneStringMap(entity.Attributes)
	return &clone
}

func cloneProjectedLink(link *ports.ProjectedLink) *ports.ProjectedLink {
	if link == nil {
		return nil
	}
	clone := *link
	clone.Attributes = cloneStringMap(link.Attributes)
	return &clone
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func sortedMapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (s *Service) prepareCheckpoint(ctx context.Context, request sourceRequest, result *IngestResult, cursor **cerebrov1.SourceCursor) (CheckpointStore, error) {
	if !request.CheckpointEnabled {
		return nil, nil
	}
	checkpointStore, ok := s.graphStore.(CheckpointStore)
	if !ok {
		return nil, ErrRuntimeUnavailable
	}
	checkpointID := checkpointID(request)
	result.CheckpointID = checkpointID
	if request.ResetCheckpoint || *cursor != nil {
		return checkpointStore, nil
	}
	checkpoint, found, err := checkpointStore.GetIngestCheckpoint(ctx, checkpointID)
	if err != nil {
		return nil, err
	}
	if !found {
		return checkpointStore, nil
	}
	result.CheckpointResumed = true
	result.CheckpointCursor = strings.TrimSpace(checkpoint.CursorOpaque)
	if checkpoint.Completed && checkpoint.CursorOpaque == "" {
		result.CheckpointComplete = true
		result.CheckpointAlreadyFresh = true
		return checkpointStore, nil
	}
	if checkpoint.CursorOpaque != "" {
		*cursor = &cerebrov1.SourceCursor{Opaque: checkpoint.CursorOpaque}
	}
	return checkpointStore, nil
}

func normalizePageLimit(pageLimit uint32) (uint32, error) {
	if pageLimit == 0 {
		return DefaultPageLimit, nil
	}
	if pageLimit > MaxPageLimit {
		return 0, fmt.Errorf("%w: page_limit must be between 1 and %d", ErrInvalidRequest, MaxPageLimit)
	}
	return pageLimit, nil
}

func normalizeFilter(filter graphstore.IngestRunFilter) (graphstore.IngestRunFilter, error) {
	limit, err := normalizeStatusLimit(uint32(filter.Limit))
	if err != nil {
		return graphstore.IngestRunFilter{}, err
	}
	filter.Limit = limit
	filter.RuntimeID = strings.TrimSpace(filter.RuntimeID)
	filter.Status = strings.TrimSpace(filter.Status)
	if filter.Status != "" && !validRunStatus(filter.Status) {
		return graphstore.IngestRunFilter{}, fmt.Errorf("%w: unsupported ingest run status %q", ErrInvalidRequest, filter.Status)
	}
	return filter, nil
}

func normalizeStatusLimit(limit uint32) (int, error) {
	if limit == 0 {
		return DefaultStatusLimit, nil
	}
	if limit > MaxStatusLimit {
		return 0, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidRequest, MaxStatusLimit)
	}
	return int(limit), nil
}

func persistCheckpoint(ctx context.Context, checkpointStore CheckpointStore, request sourceRequest, result *IngestResult, response *cerebrov1.ReadSourceResponse, nextCursor *cerebrov1.SourceCursor) error {
	cursorOpaque := ""
	completed := true
	if nextCursor != nil {
		cursorOpaque = strings.TrimSpace(nextCursor.GetOpaque())
		completed = cursorOpaque == ""
	}
	checkpoint := graphstore.IngestCheckpoint{
		ID:               checkpointID(request),
		SourceID:         strings.TrimSpace(request.SourceID),
		TenantID:         strings.TrimSpace(request.TenantID),
		ConfigHash:       configHash(request.SourceConfig),
		CursorOpaque:     cursorOpaque,
		CheckpointOpaque: strings.TrimSpace(response.GetCheckpoint().GetCursorOpaque()),
		Completed:        completed,
		PagesRead:        int64(result.PagesRead),
		EventsRead:       int64(result.EventsRead),
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := checkpointStore.PutIngestCheckpoint(ctx, checkpoint); err != nil {
		return err
	}
	result.CheckpointID = checkpoint.ID
	result.CheckpointCursor = cursorOpaque
	result.CheckpointPersisted = true
	result.CheckpointComplete = completed
	return nil
}

func checkpointID(request sourceRequest) string {
	if normalized := strings.TrimSpace(request.CheckpointID); normalized != "" {
		return normalized
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		tenantID = "default"
	}
	hash := configHash(request.SourceConfig)
	if len(hash) > 16 {
		hash = hash[:16]
	}
	return strings.TrimSpace(request.SourceID) + ":" + tenantID + ":" + hash
}

func runtimeCheckpointID(request RuntimeRequest, runtime *cerebrov1.SourceRuntime, config map[string]string) string {
	if normalized := strings.TrimSpace(request.CheckpointID); normalized != "" {
		return normalized
	}
	runtimeID := strings.TrimSpace(runtime.GetId())
	if runtimeID == "" {
		runtimeID = "unknown"
	}
	idSum := sha256.Sum256([]byte(runtimeID))
	runtimePart := hex.EncodeToString(idSum[:8])
	hash := configHash(config)
	if len(hash) > 16 {
		hash = hash[:16]
	}
	return "runtime:" + runtimePart + ":" + hash
}

func ingestTrigger(trigger string) string {
	normalized := strings.TrimSpace(trigger)
	if normalized == "" {
		return "api"
	}
	return normalized
}

func ingestRunID(runtimeID string, startedAt time.Time) string {
	return fmt.Sprintf("graph-ingest:%s:%s", sanitizeIDPart(runtimeID), startedAt.UTC().Format("20060102T150405.000000000Z"))
}

func finishRun(run graphstore.IngestRun, result *IngestResult, status string, runErr error) graphstore.IngestRun {
	finished := run
	finished.Status = status
	finished.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if result != nil {
		finished.CheckpointID = result.CheckpointID
		finished.PagesRead = int64(result.PagesRead)
		finished.EventsRead = int64(result.EventsRead)
		finished.EntitiesProjected = int64(result.EntitiesProjected)
		finished.LinksProjected = int64(result.LinksProjected)
		finished.GraphNodesBefore = result.GraphNodesBefore
		finished.GraphLinksBefore = result.GraphLinksBefore
		finished.GraphNodesAfter = result.GraphNodesAfter
		finished.GraphLinksAfter = result.GraphLinksAfter
	}
	if runErr != nil {
		finished.Error = runErr.Error()
	}
	return finished
}

func configHash(config map[string]string) string {
	keys := make([]string, 0, len(config))
	for key := range config {
		if !sourceconfig.InternalKey(key) && !sensitiveConfigKey(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	hash := sha256.New()
	for _, key := range keys {
		hash.Write([]byte(strings.TrimSpace(key)))
		hash.Write([]byte{0})
		hash.Write([]byte(config[key]))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func sensitiveConfigKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return false
	}
	for _, marker := range []string{"token", "secret", "password", "session"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(normalized)
	if strings.Contains(compact, "apikey") ||
		strings.Contains(compact, "accesskey") ||
		strings.Contains(compact, "privatekey") ||
		strings.Contains(compact, "signingkey") {
		return true
	}
	return normalized == "key"
}

func ingestEvent(event *cerebrov1.EventEnvelope, tenantID string, runtimeID string) *cerebrov1.EventEnvelope {
	if event == nil {
		return nil
	}
	cloned := proto.Clone(event).(*cerebrov1.EventEnvelope)
	if normalized := strings.TrimSpace(tenantID); normalized != "" {
		cloned.TenantId = normalized
	}
	if normalized := strings.TrimSpace(runtimeID); normalized != "" {
		if cloned.Attributes == nil {
			cloned.Attributes = map[string]string{}
		}
		cloned.Attributes[ports.EventAttributeSourceRuntimeID] = normalized
	}
	return cloned
}

func sanitizeIDPart(value string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return "unknown"
	}
	var builder strings.Builder
	lastDash := false
	for _, char := range normalized {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
			builder.WriteRune(char)
			lastDash = false
		default:
			if !lastDash {
				builder.WriteByte('-')
				lastDash = true
			}
		}
	}
	sanitized := strings.Trim(builder.String(), "-")
	if sanitized == "" {
		return "unknown"
	}
	return sanitized
}

func validRunStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case graphstore.IngestRunStatusRunning, graphstore.IngestRunStatusCompleted, graphstore.IngestRunStatusFailed:
		return true
	default:
		return false
	}
}
