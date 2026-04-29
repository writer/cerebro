package graphrebuild

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphstore"
	graphstorekuzu "github.com/writer/cerebro/internal/graphstore/kuzu"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceprojection"
)

const (
	modeSource          = "source"
	modeReplay          = "replay"
	defaultPageLimit    = 1
	maxPageLimit        = 100
	defaultEventLimit   = 100
	maxEventLimit       = 1000
	defaultPreviewLimit = 5
	maxPreviewLimit     = 20
	stageStatusSuccess  = "success"
)

type graphStore interface {
	ports.ProjectionGraphStore
	Close() error
	Counts(context.Context) (graphstore.Counts, error)
	IntegrityChecks(context.Context) ([]graphstore.IntegrityCheck, error)
	PathPatterns(context.Context, int) ([]graphstore.PathPattern, error)
	Topology(context.Context) (graphstore.Topology, error)
	SampleTraversals(context.Context, int) ([]graphstore.Traversal, error)
}

// Request configures one local graph rebuild dry-run.
type Request struct {
	Mode         string
	RuntimeID    string
	PageLimit    uint32
	EventLimit   uint32
	PreviewLimit int
}

// EventPreview captures one event consumed during the rebuild.
type EventPreview struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// ReadPagePreview captures one source page consumed during the rebuild.
type ReadPagePreview struct {
	Page             uint32 `json:"page"`
	Events           uint32 `json:"events"`
	CheckpointCursor string `json:"checkpoint_cursor,omitempty"`
	NextCursor       string `json:"next_cursor,omitempty"`
	Watermark        string `json:"watermark,omitempty"`
	FirstEventID     string `json:"first_event_id,omitempty"`
	LastEventID      string `json:"last_event_id,omitempty"`
}

// EntityPreview captures one projected entity written to the local graph.
type EntityPreview struct {
	URN        string `json:"urn"`
	EntityType string `json:"entity_type"`
	Label      string `json:"label"`
}

// LinkPreview captures one projected graph edge written to the local graph.
type LinkPreview struct {
	FromURN  string `json:"from_urn"`
	Relation string `json:"relation"`
	ToURN    string `json:"to_urn"`
}

// EventProjectionPreview captures the graph projection impact of one event.
type EventProjectionPreview struct {
	EventID           string `json:"event_id"`
	Kind              string `json:"kind"`
	EntitiesProjected uint32 `json:"entities_projected"`
	LinksProjected    uint32 `json:"links_projected"`
	GraphNodesAfter   int64  `json:"graph_nodes_after"`
	GraphLinksAfter   int64  `json:"graph_links_after"`
}

// CountPreview captures one grouped count in the rebuild output.
type CountPreview struct {
	Name  string `json:"name"`
	Count uint32 `json:"count"`
}

// StageConfirmation captures local confirmation for one rebuild stage.
type StageConfirmation struct {
	Name               string `json:"name"`
	Status             string `json:"status"`
	DurationMillis     int64  `json:"duration_ms"`
	PagesRead          uint32 `json:"pages_read,omitempty"`
	EventsRead         uint32 `json:"events_read,omitempty"`
	EntitiesProjected  uint32 `json:"entities_projected,omitempty"`
	LinksProjected     uint32 `json:"links_projected,omitempty"`
	AssertionsPassed   uint32 `json:"assertions_passed,omitempty"`
	AssertionsFailed   uint32 `json:"assertions_failed,omitempty"`
	PatternsVerified   uint32 `json:"patterns_verified,omitempty"`
	TopologyBuckets    uint32 `json:"topology_buckets,omitempty"`
	TraversalsVerified uint32 `json:"traversals_verified,omitempty"`
	GraphNodes         int64  `json:"graph_nodes,omitempty"`
	GraphLinks         int64  `json:"graph_links,omitempty"`
}

// TraversalPreview captures one sampled two-hop path returned from the local graph.
type TraversalPreview struct {
	Path           string `json:"path"`
	FromURN        string `json:"from_urn"`
	FirstRelation  string `json:"first_relation"`
	ViaURN         string `json:"via_urn"`
	SecondRelation string `json:"second_relation"`
	ToURN          string `json:"to_urn"`
}

// AssertionPreview captures one local graph integrity assertion.
type AssertionPreview struct {
	Name     string `json:"name"`
	Actual   int64  `json:"actual"`
	Expected int64  `json:"expected"`
	Passed   bool   `json:"passed"`
}

// PathPatternPreview captures one grouped two-hop graph pattern from the local graph.
type PathPatternPreview struct {
	Pattern        string `json:"pattern"`
	FromType       string `json:"from_type"`
	FirstRelation  string `json:"first_relation"`
	ViaType        string `json:"via_type"`
	SecondRelation string `json:"second_relation"`
	ToType         string `json:"to_type"`
	Count          int64  `json:"count"`
}

// TopologyPreview captures one connectivity bucket in the local graph.
type TopologyPreview struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// Result summarizes a dry-run rebuild execution.
type Result struct {
	Mode               string                    `json:"mode"`
	RuntimeID          string                    `json:"runtime_id"`
	SourceID           string                    `json:"source_id"`
	TenantID           string                    `json:"tenant_id,omitempty"`
	DryRun             bool                      `json:"dry_run"`
	PagesRead          uint32                    `json:"pages_read"`
	EventsRead         uint32                    `json:"events_read"`
	EntitiesProjected  uint32                    `json:"entities_projected"`
	LinksProjected     uint32                    `json:"links_projected"`
	GraphNodes         int64                     `json:"graph_nodes"`
	GraphLinks         int64                     `json:"graph_links"`
	StageConfirmations []*StageConfirmation      `json:"stage_confirmations,omitempty"`
	ReadPages          []*ReadPagePreview        `json:"read_pages,omitempty"`
	EventProjections   []*EventProjectionPreview `json:"event_projections,omitempty"`
	EventKinds         []*CountPreview           `json:"event_kinds,omitempty"`
	GraphEntityTypes   []*CountPreview           `json:"graph_entity_types,omitempty"`
	GraphRelationTypes []*CountPreview           `json:"graph_relation_types,omitempty"`
	GraphAssertions    []*AssertionPreview       `json:"graph_assertions,omitempty"`
	GraphPathPatterns  []*PathPatternPreview     `json:"graph_path_patterns,omitempty"`
	GraphTopology      []*TopologyPreview        `json:"graph_topology,omitempty"`
	GraphTraversals    []*TraversalPreview       `json:"graph_traversals,omitempty"`
	Events             []*EventPreview           `json:"events,omitempty"`
	PreviewEntities    []*EntityPreview          `json:"preview_entities,omitempty"`
	PreviewLinks       []*LinkPreview            `json:"preview_links,omitempty"`
}

// Service rebuilds a local graph from stored source runtimes.
type Service struct {
	registry     *sourcecdk.Registry
	runtimeStore ports.SourceRuntimeStore
	replayer     ports.EventReplayer
	openGraph    func(path string) (graphStore, error)
	makeTempDir  func() (string, error)
	removeAll    func(string) error
}

// New constructs a graph rebuild service.
func New(registry *sourcecdk.Registry, runtimeStore ports.SourceRuntimeStore, replayer ports.EventReplayer) *Service {
	return &Service{
		registry:     registry,
		runtimeStore: runtimeStore,
		replayer:     replayer,
		openGraph: func(path string) (graphStore, error) {
			return graphstorekuzu.Open(config.GraphStoreConfig{
				Driver:   config.GraphStoreDriverKuzu,
				KuzuPath: path,
			})
		},
		makeTempDir: func() (string, error) {
			return os.MkdirTemp("", "cerebro-graph-rebuild-")
		},
		removeAll: os.RemoveAll,
	}
}

// RebuildDryRun projects bounded source or append-log events into a temporary local Kuzu graph.
func (s *Service) RebuildDryRun(ctx context.Context, req Request) (_ *Result, err error) {
	if s == nil || s.runtimeStore == nil {
		return nil, fmt.Errorf("source runtime store is required")
	}
	runtimeID := strings.TrimSpace(req.RuntimeID)
	if runtimeID == "" {
		return nil, fmt.Errorf("runtime id is required")
	}
	mode, err := normalizeMode(req.Mode)
	if err != nil {
		return nil, err
	}
	resolveStart := time.Now()
	runtime, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID)
	if err != nil {
		return nil, err
	}
	result := &Result{
		Mode:      mode,
		RuntimeID: runtime.GetId(),
		SourceID:  runtime.GetSourceId(),
		TenantID:  strings.TrimSpace(runtime.GetTenantId()),
		DryRun:    true,
	}
	result.StageConfirmations = append(result.StageConfirmations, &StageConfirmation{
		Name:           "resolve_runtime",
		Status:         stageStatusSuccess,
		DurationMillis: durationMillis(resolveStart),
	})

	openStart := time.Now()
	tempDir, err := s.makeTempDir()
	if err != nil {
		return nil, fmt.Errorf("create temp graph directory: %w", err)
	}
	defer func() {
		if removeErr := s.removeAll(tempDir); removeErr != nil && err == nil {
			err = fmt.Errorf("remove temp graph directory: %w", removeErr)
		}
	}()
	graph, err := s.openGraph(filepath.Join(tempDir, "graph"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := graph.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close temp graph store: %w", closeErr)
		}
	}()
	if err := graph.Ping(ctx); err != nil {
		return nil, err
	}
	result.StageConfirmations = append(result.StageConfirmations, &StageConfirmation{
		Name:           "open_graph",
		Status:         stageStatusSuccess,
		DurationMillis: durationMillis(openStart),
	})

	previewLimit := normalizePreviewLimit(req.PreviewLimit)
	projectStart := time.Now()
	projector := newEventProjector(graph, previewLimit)
	var eventSummary *readSummary
	switch mode {
	case modeSource:
		source, err := s.lookupSource(strings.TrimSpace(runtime.GetSourceId()))
		if err != nil {
			return nil, err
		}
		readStart := time.Now()
		eventSummary, err = s.readEvents(ctx, source, runtime, normalizePageLimit(req.PageLimit), previewLimit, projector.Project)
		if err != nil {
			return nil, err
		}
		result.PagesRead = eventSummary.PagesRead
		result.ReadPages = eventSummary.Pages
		result.StageConfirmations = append(result.StageConfirmations, &StageConfirmation{
			Name:           "read_source",
			Status:         stageStatusSuccess,
			DurationMillis: durationMillis(readStart),
			PagesRead:      eventSummary.PagesRead,
			EventsRead:     eventSummary.EventsRead,
		})
	case modeReplay:
		replayStart := time.Now()
		eventSummary, err = s.replayEvents(ctx, runtime, normalizeEventLimit(req.EventLimit), previewLimit, projector.Project)
		if err != nil {
			return nil, err
		}
		result.StageConfirmations = append(result.StageConfirmations, &StageConfirmation{
			Name:           "replay_log",
			Status:         stageStatusSuccess,
			DurationMillis: durationMillis(replayStart),
			EventsRead:     eventSummary.EventsRead,
		})
	}
	result.EventsRead = eventSummary.EventsRead
	result.EventKinds = countPreviews(eventSummary.EventKinds)
	result.Events = eventPreviews(eventSummary.Events, previewLimit)

	projectSummary := projector.Summary()
	result.EntitiesProjected = projectSummary.EntitiesProjected
	result.LinksProjected = projectSummary.LinksProjected
	result.EventProjections = projectSummary.EventProjections
	result.GraphEntityTypes = projectSummary.GraphEntityTypes
	result.GraphRelationTypes = projectSummary.GraphRelationTypes
	result.PreviewEntities = projectSummary.PreviewEntities
	result.PreviewLinks = projectSummary.PreviewLinks
	result.StageConfirmations = append(result.StageConfirmations, &StageConfirmation{
		Name:              "project_graph",
		Status:            stageStatusSuccess,
		DurationMillis:    durationMillis(projectStart),
		EntitiesProjected: projectSummary.EntitiesProjected,
		LinksProjected:    projectSummary.LinksProjected,
	})

	countStart := time.Now()
	counts, err := graph.Counts(ctx)
	if err != nil {
		return nil, err
	}
	result.GraphNodes = counts.Nodes
	result.GraphLinks = counts.Relations
	result.StageConfirmations = append(result.StageConfirmations, &StageConfirmation{
		Name:           "count_graph",
		Status:         stageStatusSuccess,
		DurationMillis: durationMillis(countStart),
		GraphNodes:     counts.Nodes,
		GraphLinks:     counts.Relations,
	})

	integrityStart := time.Now()
	checks, err := graph.IntegrityChecks(ctx)
	if err != nil {
		return nil, err
	}
	result.GraphAssertions = assertionPreviews(checks)
	assertionsPassed, assertionsFailed := assertionCounts(result.GraphAssertions)
	result.StageConfirmations = append(result.StageConfirmations, &StageConfirmation{
		Name:             "verify_integrity",
		Status:           stageStatusSuccess,
		DurationMillis:   durationMillis(integrityStart),
		AssertionsPassed: assertionsPassed,
		AssertionsFailed: assertionsFailed,
	})

	patternStart := time.Now()
	patterns, err := graph.PathPatterns(ctx, previewLimit)
	if err != nil {
		return nil, err
	}
	result.GraphPathPatterns = pathPatternPreviews(patterns)
	result.StageConfirmations = append(result.StageConfirmations, &StageConfirmation{
		Name:             "verify_path_patterns",
		Status:           stageStatusSuccess,
		DurationMillis:   durationMillis(patternStart),
		PatternsVerified: uint32(len(result.GraphPathPatterns)),
	})

	topologyStart := time.Now()
	topology, err := graph.Topology(ctx)
	if err != nil {
		return nil, err
	}
	result.GraphTopology = topologyPreviews(topology)
	result.StageConfirmations = append(result.StageConfirmations, &StageConfirmation{
		Name:            "verify_topology",
		Status:          stageStatusSuccess,
		DurationMillis:  durationMillis(topologyStart),
		TopologyBuckets: uint32(len(result.GraphTopology)),
	})

	traversalStart := time.Now()
	traversals, err := graph.SampleTraversals(ctx, previewLimit)
	if err != nil {
		return nil, err
	}
	result.GraphTraversals = traversalPreviews(traversals)
	result.StageConfirmations = append(result.StageConfirmations, &StageConfirmation{
		Name:               "verify_traversals",
		Status:             stageStatusSuccess,
		DurationMillis:     durationMillis(traversalStart),
		TraversalsVerified: uint32(len(result.GraphTraversals)),
	})
	return result, nil
}

func (s *Service) lookupSource(id string) (sourcecdk.Source, error) {
	if s == nil || s.registry == nil {
		return nil, fmt.Errorf("%w: %s", sourceops.ErrSourceNotFound, id)
	}
	source, ok := s.registry.Get(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s", sourceops.ErrSourceNotFound, id)
	}
	return source, nil
}

func normalizeMode(mode string) (string, error) {
	value := strings.TrimSpace(mode)
	if value == "" {
		return modeSource, nil
	}
	switch value {
	case modeSource, modeReplay:
		return value, nil
	default:
		return "", fmt.Errorf("unsupported rebuild mode %q", value)
	}
}

func normalizePageLimit(pageLimit uint32) uint32 {
	if pageLimit == 0 {
		return defaultPageLimit
	}
	if pageLimit > maxPageLimit {
		return maxPageLimit
	}
	return pageLimit
}

func normalizeEventLimit(eventLimit uint32) uint32 {
	if eventLimit == 0 {
		return defaultEventLimit
	}
	if eventLimit > maxEventLimit {
		return maxEventLimit
	}
	return eventLimit
}

func normalizePreviewLimit(limit int) int {
	if limit <= 0 {
		return defaultPreviewLimit
	}
	if limit > maxPreviewLimit {
		return maxPreviewLimit
	}
	return limit
}

func materializeEvent(runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) *cerebrov1.EventEnvelope {
	if event == nil {
		return nil
	}
	materialized := proto.Clone(event).(*cerebrov1.EventEnvelope)
	if runtime == nil {
		return materialized
	}
	if tenantID := strings.TrimSpace(runtime.GetTenantId()); tenantID != "" {
		materialized.TenantId = tenantID
	}
	if runtimeID := strings.TrimSpace(runtime.GetId()); runtimeID != "" {
		if materialized.Attributes == nil {
			materialized.Attributes = make(map[string]string)
		}
		materialized.Attributes[ports.EventAttributeSourceRuntimeID] = runtimeID
	}
	return materialized
}

type readSummary struct {
	Events     []*cerebrov1.EventEnvelope
	Pages      []*ReadPagePreview
	PagesRead  uint32
	EventsRead uint32
	EventKinds map[string]uint32
}

type eventProcessor func(context.Context, *cerebrov1.EventEnvelope) error

func (s *Service) replayEvents(ctx context.Context, runtime *cerebrov1.SourceRuntime, eventLimit uint32, previewLimit int, process eventProcessor) (*readSummary, error) {
	if s == nil || s.replayer == nil {
		return nil, fmt.Errorf("append log replayer is required for replay mode")
	}
	replayed, err := s.replayer.Replay(ctx, ports.ReplayRequest{
		RuntimeID: strings.TrimSpace(runtime.GetId()),
		Limit:     eventLimit,
	})
	if err != nil {
		return nil, err
	}
	summary := &readSummary{EventKinds: make(map[string]uint32)}
	for _, event := range replayed {
		materialized := materializeEvent(runtime, event)
		if materialized == nil {
			continue
		}
		if len(summary.Events) < previewLimit {
			summary.Events = append(summary.Events, materialized)
		}
		summary.EventsRead++
		kind := strings.TrimSpace(materialized.GetKind())
		if kind != "" {
			summary.EventKinds[kind]++
		}
		if process != nil {
			if err := process(ctx, materialized); err != nil {
				return nil, err
			}
		}
	}
	return summary, nil
}

func (s *Service) readEvents(ctx context.Context, source sourcecdk.Source, runtime *cerebrov1.SourceRuntime, pageLimit uint32, previewLimit int, process eventProcessor) (*readSummary, error) {
	summary := &readSummary{EventKinds: make(map[string]uint32)}
	var cursor *cerebrov1.SourceCursor
	for page := uint32(0); page < pageLimit; page++ {
		pull, err := source.Read(ctx, sourcecdk.NewConfig(runtime.GetConfig()), cursor)
		if err != nil {
			return nil, fmt.Errorf("read source page %d: %w", page+1, err)
		}
		summary.PagesRead++
		summary.EventsRead += uint32(len(pull.Events))
		pageSummary := &ReadPagePreview{
			Page:             page + 1,
			Events:           uint32(len(pull.Events)),
			CheckpointCursor: checkpointCursor(pull.Checkpoint),
			NextCursor:       nextCursor(pull.NextCursor),
			Watermark:        formatWatermark(pull.Checkpoint),
		}
		if len(pull.Events) == 0 {
			summary.Pages = append(summary.Pages, pageSummary)
			if pull.NextCursor == nil {
				break
			}
			cursor = proto.Clone(pull.NextCursor).(*cerebrov1.SourceCursor)
			continue
		}
		for idx, event := range pull.Events {
			materialized := materializeEvent(runtime, event)
			if materialized == nil {
				return nil, fmt.Errorf("read source page %d: nil event at index %d", page+1, idx)
			}
			if len(summary.Events) < previewLimit {
				summary.Events = append(summary.Events, materialized)
			}
			if pageSummary.FirstEventID == "" {
				pageSummary.FirstEventID = strings.TrimSpace(materialized.GetId())
			}
			pageSummary.LastEventID = strings.TrimSpace(materialized.GetId())
			kind := strings.TrimSpace(materialized.GetKind())
			if kind != "" {
				summary.EventKinds[kind]++
			}
			if process != nil {
				if err := process(ctx, materialized); err != nil {
					return nil, err
				}
			}
		}
		summary.Pages = append(summary.Pages, pageSummary)
		if pull.NextCursor == nil {
			break
		}
		cursor = proto.Clone(pull.NextCursor).(*cerebrov1.SourceCursor)
	}
	return summary, nil
}

type projectSummary struct {
	EntitiesProjected  uint32
	LinksProjected     uint32
	EventProjections   []*EventProjectionPreview
	GraphEntityTypes   []*CountPreview
	GraphRelationTypes []*CountPreview
	PreviewEntities    []*EntityPreview
	PreviewLinks       []*LinkPreview
}

type eventProjector struct {
	graph        graphStore
	previewer    *previewGraphStore
	projector    *sourceprojection.Service
	previewLimit int
	summary      *projectSummary
}

func newEventProjector(graph graphStore, previewLimit int) *eventProjector {
	previewer := newPreviewGraphStore(graph, previewLimit)
	return &eventProjector{
		graph:        graph,
		previewer:    previewer,
		projector:    sourceprojection.New(nil, previewer),
		previewLimit: previewLimit,
		summary:      &projectSummary{},
	}
}

func (p *eventProjector) Project(ctx context.Context, event *cerebrov1.EventEnvelope) error {
	if p == nil || p.projector == nil || event == nil {
		return nil
	}
	projected, err := p.projector.Project(ctx, event)
	if err != nil {
		return fmt.Errorf("project event %q: %w", event.GetId(), err)
	}
	p.summary.EntitiesProjected += projected.EntitiesProjected
	p.summary.LinksProjected += projected.LinksProjected
	if len(p.summary.EventProjections) < p.previewLimit {
		counts, err := p.graph.Counts(ctx)
		if err != nil {
			return err
		}
		p.summary.EventProjections = append(p.summary.EventProjections, &EventProjectionPreview{
			EventID:           strings.TrimSpace(event.GetId()),
			Kind:              strings.TrimSpace(event.GetKind()),
			EntitiesProjected: projected.EntitiesProjected,
			LinksProjected:    projected.LinksProjected,
			GraphNodesAfter:   counts.Nodes,
			GraphLinksAfter:   counts.Relations,
		})
	}
	return nil
}

func (p *eventProjector) Summary() *projectSummary {
	if p == nil || p.summary == nil {
		return &projectSummary{}
	}
	p.summary.GraphEntityTypes = p.previewer.entityTypes()
	p.summary.GraphRelationTypes = p.previewer.relationTypes()
	p.summary.PreviewEntities = p.previewer.entities()
	p.summary.PreviewLinks = p.previewer.links()
	return p.summary
}

type previewGraphStore struct {
	store            graphStore
	limit            int
	entitiesBy       map[string]*EntityPreview
	linksBy          map[string]*LinkPreview
	seenEntities     map[string]struct{}
	seenLinks        map[string]struct{}
	entityTypeCounts map[string]uint32
	relationCounts   map[string]uint32
}

func newPreviewGraphStore(store graphStore, limit int) *previewGraphStore {
	return &previewGraphStore{
		store:            store,
		limit:            limit,
		entitiesBy:       make(map[string]*EntityPreview),
		linksBy:          make(map[string]*LinkPreview),
		seenEntities:     make(map[string]struct{}),
		seenLinks:        make(map[string]struct{}),
		entityTypeCounts: make(map[string]uint32),
		relationCounts:   make(map[string]uint32),
	}
}

func (s *previewGraphStore) Ping(ctx context.Context) error {
	return s.store.Ping(ctx)
}

func (s *previewGraphStore) UpsertProjectedEntity(ctx context.Context, entity *ports.ProjectedEntity) error {
	if err := s.store.UpsertProjectedEntity(ctx, entity); err != nil {
		return err
	}
	if entity == nil {
		return nil
	}
	urn := strings.TrimSpace(entity.URN)
	if urn == "" {
		return nil
	}
	if _, exists := s.seenEntities[urn]; !exists {
		s.seenEntities[urn] = struct{}{}
		entityType := strings.TrimSpace(entity.EntityType)
		if entityType != "" {
			s.entityTypeCounts[entityType]++
		}
	}
	if len(s.entitiesBy) >= s.limit {
		return nil
	}
	if _, exists := s.entitiesBy[urn]; exists {
		return nil
	}
	s.entitiesBy[urn] = &EntityPreview{
		URN:        urn,
		EntityType: strings.TrimSpace(entity.EntityType),
		Label:      strings.TrimSpace(entity.Label),
	}
	return nil
}

func (s *previewGraphStore) UpsertProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	if err := s.store.UpsertProjectedLink(ctx, link); err != nil {
		return err
	}
	if link == nil {
		return nil
	}
	key := strings.Join([]string{
		strings.TrimSpace(link.FromURN),
		strings.TrimSpace(link.Relation),
		strings.TrimSpace(link.ToURN),
	}, "|")
	if key == "||" {
		return nil
	}
	if _, exists := s.seenLinks[key]; !exists {
		s.seenLinks[key] = struct{}{}
		relation := strings.TrimSpace(link.Relation)
		if relation != "" {
			s.relationCounts[relation]++
		}
	}
	if len(s.linksBy) >= s.limit {
		return nil
	}
	if _, exists := s.linksBy[key]; exists {
		return nil
	}
	s.linksBy[key] = &LinkPreview{
		FromURN:  strings.TrimSpace(link.FromURN),
		Relation: strings.TrimSpace(link.Relation),
		ToURN:    strings.TrimSpace(link.ToURN),
	}
	return nil
}

func (s *previewGraphStore) entities() []*EntityPreview {
	entities := make([]*EntityPreview, 0, len(s.entitiesBy))
	for _, entity := range s.entitiesBy {
		entities = append(entities, entity)
	}
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].URN < entities[j].URN
	})
	return entities
}

func (s *previewGraphStore) links() []*LinkPreview {
	links := make([]*LinkPreview, 0, len(s.linksBy))
	for _, link := range s.linksBy {
		links = append(links, link)
	}
	sort.Slice(links, func(i, j int) bool {
		left := strings.Join([]string{links[i].FromURN, links[i].Relation, links[i].ToURN}, "|")
		right := strings.Join([]string{links[j].FromURN, links[j].Relation, links[j].ToURN}, "|")
		return left < right
	})
	return links
}

func (s *previewGraphStore) entityTypes() []*CountPreview {
	return countPreviews(s.entityTypeCounts)
}

func (s *previewGraphStore) relationTypes() []*CountPreview {
	return countPreviews(s.relationCounts)
}

func eventPreviews(events []*cerebrov1.EventEnvelope, limit int) []*EventPreview {
	if len(events) == 0 || limit <= 0 {
		return nil
	}
	previews := make([]*EventPreview, 0, min(limit, len(events)))
	for _, event := range events {
		if len(previews) >= limit {
			break
		}
		if event == nil {
			continue
		}
		previews = append(previews, &EventPreview{
			ID:   strings.TrimSpace(event.GetId()),
			Kind: strings.TrimSpace(event.GetKind()),
		})
	}
	return previews
}

func countPreviews(counts map[string]uint32) []*CountPreview {
	previews := make([]*CountPreview, 0, len(counts))
	for name, count := range counts {
		if strings.TrimSpace(name) == "" || count == 0 {
			continue
		}
		previews = append(previews, &CountPreview{Name: name, Count: count})
	}
	sort.Slice(previews, func(i, j int) bool {
		if previews[i].Count == previews[j].Count {
			return previews[i].Name < previews[j].Name
		}
		return previews[i].Count > previews[j].Count
	})
	return previews
}

func assertionPreviews(checks []graphstore.IntegrityCheck) []*AssertionPreview {
	previews := make([]*AssertionPreview, 0, len(checks))
	for _, check := range checks {
		previews = append(previews, &AssertionPreview{
			Name:     check.Name,
			Actual:   check.Actual,
			Expected: check.Expected,
			Passed:   check.Passed,
		})
	}
	return previews
}

func assertionCounts(assertions []*AssertionPreview) (uint32, uint32) {
	var passed uint32
	var failed uint32
	for _, assertion := range assertions {
		if assertion == nil {
			continue
		}
		if assertion.Passed {
			passed++
			continue
		}
		failed++
	}
	return passed, failed
}

func pathPatternPreviews(patterns []graphstore.PathPattern) []*PathPatternPreview {
	previews := make([]*PathPatternPreview, 0, len(patterns))
	for _, pattern := range patterns {
		previews = append(previews, &PathPatternPreview{
			Pattern:        pathPatternLabel(pattern),
			FromType:       pattern.FromType,
			FirstRelation:  pattern.FirstRelation,
			ViaType:        pattern.ViaType,
			SecondRelation: pattern.SecondRelation,
			ToType:         pattern.ToType,
			Count:          pattern.Count,
		})
	}
	return previews
}

func pathPatternLabel(pattern graphstore.PathPattern) string {
	return strings.TrimSpace(pattern.FromType) +
		" -[" + strings.TrimSpace(pattern.FirstRelation) + "]-> " +
		strings.TrimSpace(pattern.ViaType) +
		" -[" + strings.TrimSpace(pattern.SecondRelation) + "]-> " +
		strings.TrimSpace(pattern.ToType)
}

func topologyPreviews(topology graphstore.Topology) []*TopologyPreview {
	previews := []*TopologyPreview{
		{Name: "isolated", Count: topology.Isolated},
		{Name: "sources_only", Count: topology.SourcesOnly},
		{Name: "sinks_only", Count: topology.SinksOnly},
		{Name: "intermediates", Count: topology.Intermediates},
	}
	return previews
}

func traversalPreviews(traversals []graphstore.Traversal) []*TraversalPreview {
	previews := make([]*TraversalPreview, 0, len(traversals))
	for _, traversal := range traversals {
		previews = append(previews, &TraversalPreview{
			Path:           traversalPath(traversal),
			FromURN:        traversal.FromURN,
			FirstRelation:  traversal.FirstRelation,
			ViaURN:         traversal.ViaURN,
			SecondRelation: traversal.SecondRelation,
			ToURN:          traversal.ToURN,
		})
	}
	return previews
}

func traversalPath(traversal graphstore.Traversal) string {
	from := firstNonEmptyLabel(traversal.FromLabel, traversal.FromURN)
	via := firstNonEmptyLabel(traversal.ViaLabel, traversal.ViaURN)
	to := firstNonEmptyLabel(traversal.ToLabel, traversal.ToURN)
	return from + " -[" + traversal.FirstRelation + "]-> " + via + " -[" + traversal.SecondRelation + "]-> " + to
}

func firstNonEmptyLabel(label string, fallback string) string {
	if strings.TrimSpace(label) != "" {
		return strings.TrimSpace(label)
	}
	return strings.TrimSpace(fallback)
}

func durationMillis(start time.Time) int64 {
	if start.IsZero() {
		return 0
	}
	return time.Since(start).Milliseconds()
}

func formatWatermark(checkpoint *cerebrov1.SourceCheckpoint) string {
	if checkpoint == nil || checkpoint.GetWatermark() == nil || checkpoint.GetWatermark().AsTime().IsZero() {
		return ""
	}
	return checkpoint.GetWatermark().AsTime().UTC().Format(time.RFC3339Nano)
}

func checkpointCursor(checkpoint *cerebrov1.SourceCheckpoint) string {
	if checkpoint == nil {
		return ""
	}
	return strings.TrimSpace(checkpoint.GetCursorOpaque())
}

func nextCursor(cursor *cerebrov1.SourceCursor) string {
	if cursor == nil {
		return ""
	}
	return strings.TrimSpace(cursor.GetOpaque())
}

func min(left int, right int) int {
	if left < right {
		return left
	}
	return right
}
