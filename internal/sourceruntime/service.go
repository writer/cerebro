package sourceruntime

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceops"
)

const (
	defaultPageLimit = 1
	maxPageLimit     = 100
	defaultListLimit = 100
	maxListLimit     = 500
	redactedValue    = "[redacted]"
)

var (
	// ErrRuntimeUnavailable indicates that the runtime dependencies are not configured.
	ErrRuntimeUnavailable = errors.New("source runtime is unavailable")
	ErrInvalidRequest     = errors.New("invalid source runtime request")
)

// Service persists and executes source runtimes against the append log.
type Service struct {
	registry  *sourcecdk.Registry
	store     ports.SourceRuntimeStore
	appendLog ports.AppendLog
	projector ports.SourceProjector
	resolver  sourceconfig.Resolver
}

// New constructs a source runtime service.
func New(registry *sourcecdk.Registry, store ports.SourceRuntimeStore, appendLog ports.AppendLog, projector ports.SourceProjector) *Service {
	return &Service{registry: registry, store: store, appendLog: appendLog, projector: projector}
}

// WithConfigResolver configures runtime source config secret resolution.
func (s *Service) WithConfigResolver(resolver sourceconfig.Resolver) *Service {
	if s == nil {
		return nil
	}
	s.resolver = resolver
	return s
}

// Put validates and stores a source runtime definition.
func (s *Service) Put(ctx context.Context, req *cerebrov1.PutSourceRuntimeRequest) (*cerebrov1.PutSourceRuntimeResponse, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	if req == nil || req.GetRuntime() == nil {
		return nil, fmt.Errorf("%w: source runtime is required", ErrInvalidRequest)
	}
	runtime := cloneRuntime(req.GetRuntime())
	runtime.Id = strings.TrimSpace(runtime.GetId())
	runtime.SourceId = strings.TrimSpace(runtime.GetSourceId())
	runtime.TenantId = strings.TrimSpace(runtime.GetTenantId())
	if runtime.GetId() == "" {
		return nil, fmt.Errorf("%w: source runtime id is required", ErrInvalidRequest)
	}
	source, err := s.lookupSource(runtime.GetSourceId())
	if err != nil {
		return nil, err
	}
	existing, err := s.lookupRuntime(ctx, runtime.GetId())
	switch {
	case err == nil:
		restoreRedactedConfig(existing, runtime)
	case errors.Is(err, ports.ErrSourceRuntimeNotFound):
		existing = nil
	default:
		return nil, err
	}
	resolvedConfig, err := s.resolveConfig(ctx, runtime.GetSourceId(), runtime.GetConfig())
	if err != nil {
		return nil, err
	}
	if err := source.Check(ctx, sourcecdk.NewConfig(resolvedConfig)); err != nil {
		if errors.Is(err, sourcecdk.ErrInvalidConfig) {
			return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
		}
		return nil, err
	}
	if existing != nil {
		if err := validateRuntimeTenantUnchanged(existing, runtime); err != nil {
			return nil, err
		}
		runtime = mergeRuntime(existing, runtime)
	}
	if err := s.store.PutSourceRuntime(ctx, runtime); err != nil {
		return nil, err
	}
	return &cerebrov1.PutSourceRuntimeResponse{Runtime: redactRuntime(runtime)}, nil
}

// Get returns one stored source runtime definition.
func (s *Service) Get(ctx context.Context, req *cerebrov1.GetSourceRuntimeRequest) (*cerebrov1.GetSourceRuntimeResponse, error) {
	runtime, err := s.lookupRuntime(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &cerebrov1.GetSourceRuntimeResponse{Runtime: redactRuntime(runtime)}, nil
}

// List returns stored source runtime definitions.
func (s *Service) List(ctx context.Context, filter ports.SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	lister, ok := s.store.(ports.SourceRuntimeListStore)
	if !ok {
		return nil, ErrRuntimeUnavailable
	}
	normalized, err := normalizeListFilter(filter)
	if err != nil {
		return nil, err
	}
	runtimes, err := lister.ListSourceRuntimes(ctx, normalized)
	if err != nil {
		return nil, err
	}
	for i, runtime := range runtimes {
		runtimes[i] = redactRuntime(runtime)
	}
	return runtimes, nil
}

// Sync advances one stored source runtime and appends emitted events.
func (s *Service) Sync(ctx context.Context, req *cerebrov1.SyncSourceRuntimeRequest) (*cerebrov1.SyncSourceRuntimeResponse, error) {
	if s == nil || s.store == nil || s.appendLog == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtime, err := s.lookupRuntime(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	source, err := s.lookupSource(runtime.GetSourceId())
	if err != nil {
		return nil, err
	}
	runtimeConfig, err := s.resolveConfig(ctx, runtime.GetSourceId(), runtime.GetConfig())
	if err != nil {
		return nil, err
	}
	pageLimit, err := normalizePageLimit(req.GetPageLimit())
	if err != nil {
		return nil, err
	}
	cursor := cloneCursor(runtime.GetNextCursor())
	var (
		eventsAppended    uint32
		pagesRead         uint32
		entitiesProjected uint32
		linksProjected    uint32
	)
	for i := uint32(0); i < pageLimit; i++ {
		pull, err := source.Read(ctx, sourcecdk.NewConfig(runtimeConfig), cursor)
		if err != nil {
			return nil, err
		}
		if pull.Checkpoint != nil {
			runtime.Checkpoint = cloneCheckpoint(pull.Checkpoint)
		}
		runtime.NextCursor = cloneCursor(pull.NextCursor)
		pagesRead++
		for _, event := range pull.Events {
			syncedEvent := materializeEvent(runtime, event)
			if err := s.appendLog.Append(ctx, syncedEvent); err != nil {
				return nil, fmt.Errorf("append source event %q: %w", syncedEvent.GetId(), err)
			}
			eventsAppended++
			if s.projector != nil {
				result, err := s.projector.Project(ctx, syncedEvent)
				if err != nil {
					return nil, fmt.Errorf("project source event %q: %w", syncedEvent.GetId(), err)
				}
				entitiesProjected += result.EntitiesProjected
				linksProjected += result.LinksProjected
			}
		}
		runtime.LastSyncedAt = timestamppb.Now()
		if err := s.store.PutSourceRuntime(ctx, runtime); err != nil {
			return nil, err
		}
		if pull.NextCursor == nil {
			break
		}
		cursor = cloneCursor(pull.NextCursor)
	}
	return &cerebrov1.SyncSourceRuntimeResponse{
		Runtime:           redactRuntime(runtime),
		Source:            source.Spec(),
		PagesRead:         pagesRead,
		EventsAppended:    eventsAppended,
		EntitiesProjected: entitiesProjected,
		LinksProjected:    linksProjected,
	}, nil
}

func (s *Service) resolveConfig(ctx context.Context, sourceID string, config map[string]string) (map[string]string, error) {
	resolver := s.resolver
	if resolver == nil {
		return cloneConfig(config), nil
	}
	return resolver(ctx, sourceID, config)
}

func (s *Service) lookupSource(sourceID string) (sourcecdk.Source, error) {
	id := strings.TrimSpace(sourceID)
	if id == "" {
		return nil, fmt.Errorf("%w: source id is required", ErrInvalidRequest)
	}
	if s == nil || s.registry == nil {
		return nil, fmt.Errorf("%w: %s", sourceops.ErrSourceNotFound, id)
	}
	source, ok := s.registry.Get(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s", sourceops.ErrSourceNotFound, id)
	}
	return source, nil
}

func (s *Service) lookupRuntime(ctx context.Context, runtimeID string) (*cerebrov1.SourceRuntime, error) {
	id := strings.TrimSpace(runtimeID)
	if id == "" {
		return nil, fmt.Errorf("%w: source runtime id is required", ErrInvalidRequest)
	}
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtime, err := s.store.GetSourceRuntime(ctx, id)
	if err != nil {
		return nil, err
	}
	return runtime, nil
}

func normalizePageLimit(pageLimit uint32) (uint32, error) {
	if pageLimit == 0 {
		return defaultPageLimit, nil
	}
	if pageLimit > maxPageLimit {
		return 0, fmt.Errorf("%w: page_limit must be between 1 and %d", ErrInvalidRequest, maxPageLimit)
	}
	return pageLimit, nil
}

func normalizeListFilter(filter ports.SourceRuntimeFilter) (ports.SourceRuntimeFilter, error) {
	normalized := ports.SourceRuntimeFilter{
		TenantID: strings.TrimSpace(filter.TenantID),
		SourceID: strings.TrimSpace(filter.SourceID),
		Limit:    filter.Limit,
	}
	if normalized.Limit == 0 {
		normalized.Limit = defaultListLimit
	}
	if normalized.Limit > maxListLimit {
		return ports.SourceRuntimeFilter{}, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidRequest, maxListLimit)
	}
	return normalized, nil
}

func restoreRedactedConfig(existing *cerebrov1.SourceRuntime, incoming *cerebrov1.SourceRuntime) {
	if existing == nil || incoming == nil || len(incoming.GetConfig()) == 0 {
		return
	}
	if strings.TrimSpace(existing.GetSourceId()) != strings.TrimSpace(incoming.GetSourceId()) {
		return
	}
	for key, value := range incoming.GetConfig() {
		if strings.TrimSpace(value) != redactedValue || !sensitiveConfigKey(key) {
			continue
		}
		if preserved, ok := existing.GetConfig()[key]; ok {
			incoming.Config[key] = preserved
		}
	}
}

func mergeRuntime(existing *cerebrov1.SourceRuntime, incoming *cerebrov1.SourceRuntime) *cerebrov1.SourceRuntime {
	if existing == nil {
		return incoming
	}
	if strings.TrimSpace(incoming.GetTenantId()) == "" {
		incoming.TenantId = strings.TrimSpace(existing.GetTenantId())
	}
	resetProgress := existing.GetSourceId() != incoming.GetSourceId() ||
		existing.GetTenantId() != incoming.GetTenantId() ||
		!sameConfig(existing.GetConfig(), incoming.GetConfig())
	if !resetProgress {
		incoming.Checkpoint = cloneCheckpoint(existing.GetCheckpoint())
		incoming.NextCursor = cloneCursor(existing.GetNextCursor())
		incoming.LastSyncedAt = cloneTimestamp(existing.GetLastSyncedAt())
	}
	return incoming
}

func validateRuntimeTenantUnchanged(existing *cerebrov1.SourceRuntime, incoming *cerebrov1.SourceRuntime) error {
	existingTenantID := strings.TrimSpace(existing.GetTenantId())
	incomingTenantID := strings.TrimSpace(incoming.GetTenantId())
	if existingTenantID == "" || incomingTenantID == "" || existingTenantID == incomingTenantID {
		return nil
	}
	return fmt.Errorf("%w: source runtime tenant_id cannot be changed", ErrInvalidRequest)
}

func materializeEvent(runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) *cerebrov1.EventEnvelope {
	if event == nil {
		return nil
	}
	cloned := proto.Clone(event).(*cerebrov1.EventEnvelope)
	if runtime == nil {
		return cloned
	}
	if strings.TrimSpace(runtime.GetTenantId()) != "" {
		cloned.TenantId = strings.TrimSpace(runtime.GetTenantId())
	}
	if strings.TrimSpace(runtime.GetId()) != "" {
		if cloned.Attributes == nil {
			cloned.Attributes = make(map[string]string)
		}
		cloned.Attributes[ports.EventAttributeSourceRuntimeID] = strings.TrimSpace(runtime.GetId())
	}
	return cloned
}

func sameConfig(left map[string]string, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		other, ok := right[key]
		if !ok || other != value {
			return false
		}
	}
	return true
}

func cloneConfig(config map[string]string) map[string]string {
	cloned := make(map[string]string, len(config))
	for key, value := range config {
		cloned[key] = value
	}
	return cloned
}

func redactRuntime(runtime *cerebrov1.SourceRuntime) *cerebrov1.SourceRuntime {
	cloned := cloneRuntime(runtime)
	if cloned == nil {
		return nil
	}
	redacted := make(map[string]string, len(cloned.GetConfig()))
	for key, value := range cloned.GetConfig() {
		if sensitiveConfigKey(key) {
			redacted[key] = redactedValue
			continue
		}
		redacted[key] = value
	}
	cloned.Config = redacted
	return cloned
}

func sensitiveConfigKey(key string) bool {
	value := strings.ToLower(strings.TrimSpace(key))
	if value == "" {
		return false
	}
	if strings.Contains(value, "token") || strings.Contains(value, "secret") || strings.Contains(value, "password") {
		return true
	}
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(value)
	if strings.Contains(compact, "apikey") || strings.Contains(compact, "accesskey") || strings.Contains(compact, "privatekey") {
		return true
	}
	return value == "key" || strings.HasSuffix(value, "_key")
}

func cloneRuntime(runtime *cerebrov1.SourceRuntime) *cerebrov1.SourceRuntime {
	if runtime == nil {
		return nil
	}
	return proto.Clone(runtime).(*cerebrov1.SourceRuntime)
}

func cloneCursor(cursor *cerebrov1.SourceCursor) *cerebrov1.SourceCursor {
	if cursor == nil {
		return nil
	}
	return proto.Clone(cursor).(*cerebrov1.SourceCursor)
}

func cloneCheckpoint(checkpoint *cerebrov1.SourceCheckpoint) *cerebrov1.SourceCheckpoint {
	if checkpoint == nil {
		return nil
	}
	return proto.Clone(checkpoint).(*cerebrov1.SourceCheckpoint)
}

func cloneTimestamp(value *timestamppb.Timestamp) *timestamppb.Timestamp {
	if value == nil {
		return nil
	}
	return proto.Clone(value).(*timestamppb.Timestamp)
}
