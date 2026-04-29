package graphrebuild

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	graphstorekuzu "github.com/writer/cerebro/internal/graphstore/kuzu"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceprojection"
)

const (
	defaultPageLimit    = 1
	maxPageLimit        = 100
	defaultPreviewLimit = 5
	maxPreviewLimit     = 20
)

type graphStore interface {
	ports.ProjectionGraphStore
	Close() error
	Counts(context.Context) (graphstorekuzu.Counts, error)
}

// Request configures one local graph rebuild dry-run.
type Request struct {
	RuntimeID    string
	PageLimit    uint32
	PreviewLimit int
}

// EventPreview captures one event consumed during the rebuild.
type EventPreview struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
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

// Result summarizes a dry-run rebuild execution.
type Result struct {
	RuntimeID         string           `json:"runtime_id"`
	SourceID          string           `json:"source_id"`
	TenantID          string           `json:"tenant_id,omitempty"`
	DryRun            bool             `json:"dry_run"`
	PagesRead         uint32           `json:"pages_read"`
	EventsRead        uint32           `json:"events_read"`
	EntitiesProjected uint32           `json:"entities_projected"`
	LinksProjected    uint32           `json:"links_projected"`
	GraphNodes        int64            `json:"graph_nodes"`
	GraphLinks        int64            `json:"graph_links"`
	Events            []*EventPreview  `json:"events,omitempty"`
	PreviewEntities   []*EntityPreview `json:"preview_entities,omitempty"`
	PreviewLinks      []*LinkPreview   `json:"preview_links,omitempty"`
}

// Service rebuilds a local graph from stored source runtimes.
type Service struct {
	registry     *sourcecdk.Registry
	runtimeStore ports.SourceRuntimeStore
	openGraph    func(path string) (graphStore, error)
	makeTempDir  func() (string, error)
	removeAll    func(string) error
}

// New constructs a graph rebuild service.
func New(registry *sourcecdk.Registry, runtimeStore ports.SourceRuntimeStore) *Service {
	return &Service{
		registry:     registry,
		runtimeStore: runtimeStore,
		openGraph: func(path string) (graphStore, error) {
			return graphstorekuzu.Open(config.GraphStoreConfig{
				Driver:   "kuzu",
				KuzuPath: path,
			})
		},
		makeTempDir: func() (string, error) {
			return os.MkdirTemp("", "cerebro-graph-rebuild-")
		},
		removeAll: os.RemoveAll,
	}
}

// RebuildDryRun projects a bounded number of source pages into a temporary local Kuzu graph.
func (s *Service) RebuildDryRun(ctx context.Context, req Request) (_ *Result, err error) {
	if s == nil || s.runtimeStore == nil {
		return nil, fmt.Errorf("source runtime store is required")
	}
	runtimeID := strings.TrimSpace(req.RuntimeID)
	if runtimeID == "" {
		return nil, fmt.Errorf("runtime id is required")
	}
	runtime, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID)
	if err != nil {
		return nil, err
	}
	source, err := s.lookupSource(strings.TrimSpace(runtime.GetSourceId()))
	if err != nil {
		return nil, err
	}
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

	previewer := newPreviewGraphStore(graph, normalizePreviewLimit(req.PreviewLimit))
	projector := sourceprojection.New(nil, previewer)
	pageLimit := normalizePageLimit(req.PageLimit)

	result := &Result{
		RuntimeID: runtime.GetId(),
		SourceID:  runtime.GetSourceId(),
		TenantID:  strings.TrimSpace(runtime.GetTenantId()),
		DryRun:    true,
	}
	var cursor *cerebrov1.SourceCursor
	for page := uint32(0); page < pageLimit; page++ {
		pull, err := source.Read(ctx, sourcecdk.NewConfig(runtime.GetConfig()), cursor)
		if err != nil {
			return nil, fmt.Errorf("read source page %d: %w", page+1, err)
		}
		if len(pull.Events) == 0 {
			break
		}
		result.PagesRead++
		result.EventsRead += uint32(len(pull.Events))
		for idx, event := range pull.Events {
			materialized := materializeEvent(runtime, event)
			if materialized == nil {
				return nil, fmt.Errorf("read source page %d: nil event at index %d", page+1, idx)
			}
			previewer.addEvent(materialized)
			projected, err := projector.Project(ctx, materialized)
			if err != nil {
				return nil, fmt.Errorf("project event %q: %w", materialized.GetId(), err)
			}
			result.EntitiesProjected += projected.EntitiesProjected
			result.LinksProjected += projected.LinksProjected
		}
		if pull.NextCursor == nil {
			break
		}
		cursor = proto.Clone(pull.NextCursor).(*cerebrov1.SourceCursor)
	}

	counts, err := graph.Counts(ctx)
	if err != nil {
		return nil, err
	}
	result.GraphNodes = counts.Nodes
	result.GraphLinks = counts.Relations
	result.Events = previewer.events()
	result.PreviewEntities = previewer.entities()
	result.PreviewLinks = previewer.links()
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

func normalizePageLimit(pageLimit uint32) uint32 {
	if pageLimit == 0 {
		return defaultPageLimit
	}
	if pageLimit > maxPageLimit {
		return maxPageLimit
	}
	return pageLimit
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
	return materialized
}

type previewGraphStore struct {
	store      graphStore
	limit      int
	eventItems []*EventPreview
	entitiesBy map[string]*EntityPreview
	linksBy    map[string]*LinkPreview
}

func newPreviewGraphStore(store graphStore, limit int) *previewGraphStore {
	return &previewGraphStore{
		store:      store,
		limit:      limit,
		entitiesBy: make(map[string]*EntityPreview),
		linksBy:    make(map[string]*LinkPreview),
	}
}

func (s *previewGraphStore) Ping(ctx context.Context) error {
	return s.store.Ping(ctx)
}

func (s *previewGraphStore) UpsertProjectedEntity(ctx context.Context, entity *ports.ProjectedEntity) error {
	if err := s.store.UpsertProjectedEntity(ctx, entity); err != nil {
		return err
	}
	if entity == nil || len(s.entitiesBy) >= s.limit {
		return nil
	}
	urn := strings.TrimSpace(entity.URN)
	if urn == "" {
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
	if link == nil || len(s.linksBy) >= s.limit {
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

func (s *previewGraphStore) addEvent(event *cerebrov1.EventEnvelope) {
	if event == nil || len(s.eventItems) >= s.limit {
		return
	}
	s.eventItems = append(s.eventItems, &EventPreview{
		ID:   strings.TrimSpace(event.GetId()),
		Kind: strings.TrimSpace(event.GetKind()),
	})
}

func (s *previewGraphStore) events() []*EventPreview {
	events := append([]*EventPreview(nil), s.eventItems...)
	sort.Slice(events, func(i, j int) bool {
		if events[i].ID == events[j].ID {
			return events[i].Kind < events[j].Kind
		}
		return events[i].ID < events[j].ID
	})
	return events
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
