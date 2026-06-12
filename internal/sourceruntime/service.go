package sourceruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/telemetry"
)

const (
	defaultPageLimit = 1
	maxPageLimit     = 100
	defaultListLimit = 100
	maxListLimit     = 500
	redactedValue    = "[redacted]"

	runtimeProgressConfigHashKey = "__cerebro_resolved_progress_config_hash"

	runtimeStatusConfigKey                = "__cerebro_runtime_status"
	runtimeRecordsScannedConfigKey        = "__cerebro_runtime_records_scanned"
	runtimeRecordsAcceptedConfigKey       = "__cerebro_runtime_records_accepted"
	runtimeRecordsRejectedConfigKey       = "__cerebro_runtime_records_rejected"
	runtimeEntitiesProjectedConfigKey     = "__cerebro_runtime_entities_projected"
	runtimeLinksProjectedConfigKey        = "__cerebro_runtime_links_projected"
	runtimeLastFailureCategoryConfigKey   = "__cerebro_runtime_last_failure_category"
	runtimeLastInvalidEventIDConfigKey    = "__cerebro_runtime_last_invalid_event_id"
	runtimeLastInvalidFieldConfigKey      = "__cerebro_runtime_last_invalid_field"
	runtimeLastInvalidStatusConfigKey     = "__cerebro_runtime_last_invalid_status"
	runtimeLastInvalidObservedAtConfigKey = "__cerebro_runtime_last_invalid_observed_at"
	runtimeLastInvalidOccurredAtConfigKey = "__cerebro_runtime_last_invalid_occurred_at"
	runtimeLastInvalidDiagnosticConfigKey = "__cerebro_runtime_last_invalid_diagnostic"
	runtimeLastInvalidRetryableConfigKey  = "__cerebro_runtime_last_invalid_retryable"
	runtimeContractProbeStateConfigKey    = "__cerebro_runtime_contract_probe_state"
	runtimeLastSyncWatermarkConfigKey     = "__cerebro_runtime_last_sync_watermark"
	runtimeLastSyncCompletedAtConfigKey   = "__cerebro_runtime_last_sync_completed_at"
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

// PutRuntimesRequest contains source runtime definitions to validate and store together.
type PutRuntimesRequest struct {
	Runtimes []*cerebrov1.SourceRuntime
}

// PutRuntimesResponse contains stored source runtime definitions with sensitive config redacted.
type PutRuntimesResponse struct {
	Runtimes []*cerebrov1.SourceRuntime
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
	runtime, err := s.preparePutRuntime(ctx, req.GetRuntime())
	if err != nil {
		return nil, err
	}
	if err := s.store.PutSourceRuntime(ctx, runtime); err != nil {
		return nil, err
	}
	return &cerebrov1.PutSourceRuntimeResponse{Runtime: redactRuntime(runtime)}, nil
}

// PutRuntimes validates all runtimes, then stores them atomically when more than one runtime is provided.
func (s *Service) PutRuntimes(ctx context.Context, req PutRuntimesRequest) (*PutRuntimesResponse, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	if len(req.Runtimes) == 0 {
		return nil, fmt.Errorf("%w: at least one source runtime is required", ErrInvalidRequest)
	}
	seenRuntimeIDs := make(map[string]struct{}, len(req.Runtimes))
	runtimes := make([]*cerebrov1.SourceRuntime, 0, len(req.Runtimes))
	for index, runtime := range req.Runtimes {
		prepared, err := s.preparePutRuntime(ctx, runtime)
		if err != nil {
			return nil, fmt.Errorf("source runtime %d: %w", index, err)
		}
		if _, ok := seenRuntimeIDs[prepared.GetId()]; ok {
			return nil, fmt.Errorf("%w: duplicate source runtime id %q", ErrInvalidRequest, prepared.GetId())
		}
		seenRuntimeIDs[prepared.GetId()] = struct{}{}
		runtimes = append(runtimes, prepared)
	}
	if len(runtimes) == 1 {
		if err := s.store.PutSourceRuntime(ctx, runtimes[0]); err != nil {
			return nil, err
		}
	} else {
		batchStore, ok := s.store.(ports.SourceRuntimeBatchStore)
		if !ok {
			return nil, fmt.Errorf("%w: atomic source runtime batch store is unavailable", ErrRuntimeUnavailable)
		}
		if err := batchStore.PutSourceRuntimes(ctx, runtimes); err != nil {
			return nil, err
		}
	}
	redacted := make([]*cerebrov1.SourceRuntime, 0, len(runtimes))
	for _, runtime := range runtimes {
		redacted = append(redacted, redactRuntime(runtime))
	}
	return &PutRuntimesResponse{Runtimes: redacted}, nil
}

func (s *Service) preparePutRuntime(ctx context.Context, input *cerebrov1.SourceRuntime) (*cerebrov1.SourceRuntime, error) {
	if input == nil {
		return nil, fmt.Errorf("%w: source runtime is required", ErrInvalidRequest)
	}
	runtime := cloneRuntime(input)
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
		if runtime.GetTenantId() == "" {
			runtime.TenantId = strings.TrimSpace(existing.GetTenantId())
		}
		if err := validateRuntimeTenantUnchanged(existing, runtime); err != nil {
			return nil, err
		}
	case errors.Is(err, ports.ErrSourceRuntimeNotFound):
		existing = nil
	default:
		return nil, err
	}
	resolvedConfig, err := s.resolveConfigWithOptions(ctx, runtime.GetSourceId(), runtime.GetTenantId(), runtime.GetConfig(), legacyTenantlessAssumeRoleUpdate(existing, runtime))
	if err != nil {
		return nil, err
	}
	if err := source.Check(ctx, sourcecdk.NewConfig(resolvedConfig)); err != nil {
		if errors.Is(err, sourcecdk.ErrInvalidConfig) {
			return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
		}
		return nil, err
	}
	runtime.Config = configWithProgressHash(runtime.GetConfig(), resolvedConfig)
	if existing != nil {
		runtime = mergeRuntime(existing, runtime)
	}
	return runtime, nil
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
func (s *Service) Sync(ctx context.Context, req *cerebrov1.SyncSourceRuntimeRequest) (response *cerebrov1.SyncSourceRuntimeResponse, err error) {
	runtimeID := ""
	if req != nil {
		runtimeID = strings.TrimSpace(req.GetId())
	}
	ctx, span := telemetry.Start(ctx, "source_runtime.sync", telemetry.Attrs(
		telemetry.Field{Key: "runtime_id", Value: runtimeID},
		telemetry.Field{Key: "page_limit", Value: req.GetPageLimit()},
	))
	status := "failed"
	spanAttributes := telemetry.Attrs()
	defer func() {
		if err != nil {
			status = "failed"
			spanAttributes = spanAttributes.WithField(telemetry.Field{Key: "error_kind", Value: sourceRuntimeTelemetryErrorKind(err)})
		}
		telemetry.End(span, status, spanAttributes)
	}()
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
	runtimeConfig, err := s.resolveConfigWithOptions(ctx, runtime.GetSourceId(), runtime.GetTenantId(), runtime.GetConfig(), legacyTenantlessAssumeRoleRuntime(runtime))
	if err != nil {
		return nil, err
	}
	spanAttributes = spanAttributes.WithField(telemetry.Field{Key: "source_id", Value: runtime.GetSourceId()})
	spanAttributes = spanAttributes.WithField(telemetry.Field{Key: "tenant_id", Value: runtime.GetTenantId()})
	refreshRuntimeProgressConfig(runtime, runtimeConfig)
	pageLimit, err := normalizePageLimit(req.GetPageLimit())
	if err != nil {
		return nil, err
	}
	cursor := runtimeStartCursor(runtime)
	var (
		eventsAppended    uint32
		pagesRead         uint32
		recordsScanned    uint32
		recordsRejected   uint32
		entitiesProjected uint32
		linksProjected    uint32
	)
	var eventContracts []sourcecdk.EventContract
	if provider, ok := source.(sourcecdk.EventContractProvider); ok {
		eventContracts = provider.EventContracts()
	}
	for i := uint32(0); i < pageLimit; i++ {
		pull, err := source.Read(ctx, sourcecdk.NewConfig(runtimeConfig), cursor)
		if err != nil {
			return nil, err
		}
		pageNumber := i + 1
		eventsRead := boundedUint32(len(pull.Events))
		recordsScanned += eventsRead
		telemetry.Event(ctx, "source_runtime.page_read", telemetry.Attrs(
			telemetry.Field{Key: "runtime_id", Value: runtime.GetId()},
			telemetry.Field{Key: "source_id", Value: runtime.GetSourceId()},
			telemetry.Field{Key: "tenant_id", Value: runtime.GetTenantId()},
			telemetry.Field{Key: "page", Value: pageNumber},
			telemetry.Field{Key: "events_read", Value: eventsRead},
			telemetry.Field{Key: "has_next_cursor", Value: pull.NextCursor != nil},
		))
		if pull.Checkpoint != nil {
			runtime.Checkpoint = cloneCheckpoint(pull.Checkpoint)
		}
		runtime.NextCursor = cloneCursor(pull.NextCursor)
		pagesRead++
		for _, event := range pull.Events {
			syncedEvent := materializeEvent(runtime, event)
			if syncedEvent == nil {
				continue
			}
			if err := sourcecdk.ValidateEventEnvelope(syncedEvent); err != nil {
				return nil, fmt.Errorf("validate source event %q: %w", syncedEvent.GetId(), err)
			}
			if err := sourcecdk.ValidateEventEnvelopeWithContracts(syncedEvent, eventContracts); err != nil {
				if quarantinableContractError(err) {
					recordsRejected++
					category := invalidEventFailureCategory(err)
					recordRuntimeInvalidEvent(runtime, syncedEvent, category, err, time.Now().UTC(), len(eventContracts) > 0)
					telemetry.Event(ctx, "source_runtime.invalid_event", telemetry.Attrs(
						telemetry.Field{Key: "runtime_id", Value: runtime.GetId()},
						telemetry.Field{Key: "source_id", Value: runtime.GetSourceId()},
						telemetry.Field{Key: "tenant_id", Value: runtime.GetTenantId()},
						telemetry.Field{Key: "failure_category", Value: category},
						telemetry.Field{Key: "retryable", Value: false},
					))
					continue
				}
				return nil, fmt.Errorf("validate source event %q: %w", syncedEvent.GetId(), err)
			}
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
		updateRuntimeSyncStatus(runtime, runtimeSyncStatus{
			Status:             "completed",
			RecordsScanned:     recordsScanned,
			RecordsAccepted:    eventsAppended,
			RecordsRejected:    recordsRejected,
			EntitiesProjected:  entitiesProjected,
			LinksProjected:     linksProjected,
			CompletedAt:        runtime.GetLastSyncedAt().AsTime().UTC(),
			ContractConfigured: len(eventContracts) > 0,
		})
		if err := s.store.PutSourceRuntime(ctx, runtime); err != nil {
			return nil, err
		}
		telemetry.Event(ctx, "source_runtime.page_committed", telemetry.Attrs(
			telemetry.Field{Key: "runtime_id", Value: runtime.GetId()},
			telemetry.Field{Key: "source_id", Value: runtime.GetSourceId()},
			telemetry.Field{Key: "tenant_id", Value: runtime.GetTenantId()},
			telemetry.Field{Key: "page", Value: pageNumber},
			telemetry.Field{Key: "records_scanned", Value: recordsScanned},
			telemetry.Field{Key: "records_accepted", Value: eventsAppended},
			telemetry.Field{Key: "records_rejected", Value: recordsRejected},
			telemetry.Field{Key: "events_appended", Value: eventsAppended},
			telemetry.Field{Key: "entities_projected", Value: entitiesProjected},
			telemetry.Field{Key: "links_projected", Value: linksProjected},
			telemetry.Field{Key: "has_next_cursor", Value: pull.NextCursor != nil},
		))
		if pull.NextCursor == nil {
			break
		}
		cursor = cloneCursor(pull.NextCursor)
	}
	status = "completed"
	spanAttributes = spanAttributes.WithField(telemetry.Field{Key: "pages_read", Value: pagesRead})
	spanAttributes = spanAttributes.WithField(telemetry.Field{Key: "records_scanned", Value: recordsScanned})
	spanAttributes = spanAttributes.WithField(telemetry.Field{Key: "records_accepted", Value: eventsAppended})
	spanAttributes = spanAttributes.WithField(telemetry.Field{Key: "records_rejected", Value: recordsRejected})
	spanAttributes = spanAttributes.WithField(telemetry.Field{Key: "events_appended", Value: eventsAppended})
	spanAttributes = spanAttributes.WithField(telemetry.Field{Key: "entities_projected", Value: entitiesProjected})
	spanAttributes = spanAttributes.WithField(telemetry.Field{Key: "links_projected", Value: linksProjected})
	spanAttributes = spanAttributes.WithField(telemetry.Field{Key: "has_next_cursor", Value: runtime.GetNextCursor() != nil})
	if watermark, lagSeconds, ok := runtimeWatermarkLag(runtime, time.Now().UTC()); ok {
		spanAttributes = spanAttributes.WithField(telemetry.Field{Key: "checkpoint_watermark", Value: watermark.Format(time.RFC3339Nano)})
		spanAttributes = spanAttributes.WithField(telemetry.Field{Key: "source_runtime_watermark_lag_seconds", Value: lagSeconds})
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

func sourceRuntimeTelemetryErrorKind(err error) string {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return "invalid_request"
	case errors.Is(err, ErrRuntimeUnavailable):
		return "runtime_unavailable"
	case errors.Is(err, ports.ErrSourceRuntimeNotFound):
		return "runtime_not_found"
	case errors.Is(err, sourcecdk.ErrInvalidEventEnvelope):
		return "invalid_event"
	case errors.Is(err, sourcecdk.ErrInvalidConfig):
		return "invalid_source_config"
	default:
		return "sync_failed"
	}
}

type runtimeSyncStatus struct {
	Status             string
	RecordsScanned     uint32
	RecordsAccepted    uint32
	RecordsRejected    uint32
	EntitiesProjected  uint32
	LinksProjected     uint32
	CompletedAt        time.Time
	ContractConfigured bool
}

func updateRuntimeSyncStatus(runtime *cerebrov1.SourceRuntime, status runtimeSyncStatus) {
	if runtime == nil {
		return
	}
	if runtime.Config == nil {
		runtime.Config = map[string]string{}
	}
	setRuntimeConfig(runtime.Config, runtimeStatusConfigKey, status.Status)
	setRuntimeConfig(runtime.Config, runtimeRecordsScannedConfigKey, fmt.Sprint(status.RecordsScanned))
	setRuntimeConfig(runtime.Config, runtimeRecordsAcceptedConfigKey, fmt.Sprint(status.RecordsAccepted))
	setRuntimeConfig(runtime.Config, runtimeRecordsRejectedConfigKey, fmt.Sprint(status.RecordsRejected))
	setRuntimeConfig(runtime.Config, runtimeEntitiesProjectedConfigKey, fmt.Sprint(status.EntitiesProjected))
	setRuntimeConfig(runtime.Config, runtimeLinksProjectedConfigKey, fmt.Sprint(status.LinksProjected))
	if !status.CompletedAt.IsZero() {
		setRuntimeConfig(runtime.Config, runtimeLastSyncCompletedAtConfigKey, status.CompletedAt.UTC().Format(time.RFC3339Nano))
	}
	if watermark := timestampValue(runtime.GetCheckpoint().GetWatermark()); !watermark.IsZero() {
		setRuntimeConfig(runtime.Config, runtimeLastSyncWatermarkConfigKey, watermark.UTC().Format(time.RFC3339Nano))
	}
	if status.RecordsRejected == 0 {
		clearRuntimeInvalidEvent(runtime.Config)
	}
	if strings.TrimSpace(runtime.Config[runtimeLastFailureCategoryConfigKey]) == "" {
		setRuntimeConfig(runtime.Config, runtimeContractProbeStateConfigKey, contractProbeStateForRuntime(runtime, "", status.ContractConfigured))
		return
	}
	setRuntimeConfig(runtime.Config, runtimeContractProbeStateConfigKey, contractProbeStateForRuntime(runtime, runtime.Config[runtimeLastFailureCategoryConfigKey], status.ContractConfigured))
}

func clearRuntimeInvalidEvent(config map[string]string) {
	for _, key := range []string{
		runtimeLastFailureCategoryConfigKey,
		runtimeLastInvalidEventIDConfigKey,
		runtimeLastInvalidFieldConfigKey,
		runtimeLastInvalidStatusConfigKey,
		runtimeLastInvalidObservedAtConfigKey,
		runtimeLastInvalidOccurredAtConfigKey,
		runtimeLastInvalidDiagnosticConfigKey,
		runtimeLastInvalidRetryableConfigKey,
	} {
		delete(config, key)
	}
}

func quarantinableContractError(err error) bool {
	message := err.Error()
	return strings.Contains(message, "missing required attribute") || strings.Contains(message, "missing required payload field")
}

func invalidEventFailureCategory(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "missing required attribute"):
		return "missing_required_attribute"
	case strings.Contains(message, "missing required payload field"):
		return "missing_required_payload_field"
	default:
		return "invalid_event"
	}
}

func recordRuntimeInvalidEvent(runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope, category string, cause error, observedAt time.Time, contractConfigured bool) {
	if runtime == nil || event == nil {
		return
	}
	if runtime.Config == nil {
		runtime.Config = map[string]string{}
	}
	field := invalidEventFieldName(cause)
	setRuntimeConfig(runtime.Config, runtimeLastFailureCategoryConfigKey, category)
	setRuntimeConfig(runtime.Config, runtimeLastInvalidEventIDConfigKey, firstNonEmptyString(event.GetAttributes()["source_event_id"], event.GetId()))
	setRuntimeConfig(runtime.Config, runtimeLastInvalidFieldConfigKey, field)
	setRuntimeConfig(runtime.Config, runtimeLastInvalidStatusConfigKey, "terminal")
	setRuntimeConfig(runtime.Config, runtimeLastInvalidRetryableConfigKey, "false")
	setRuntimeConfig(runtime.Config, runtimeLastInvalidObservedAtConfigKey, observedAt.UTC().Format(time.RFC3339Nano))
	if occurred := timestampValue(event.GetOccurredAt()); !occurred.IsZero() {
		setRuntimeConfig(runtime.Config, runtimeLastInvalidOccurredAtConfigKey, occurred.UTC().Format(time.RFC3339Nano))
	}
	if field != "" {
		setRuntimeConfig(runtime.Config, runtimeLastInvalidDiagnosticConfigKey, "missing required field "+field)
	} else {
		setRuntimeConfig(runtime.Config, runtimeLastInvalidDiagnosticConfigKey, "invalid source event")
	}
	setRuntimeConfig(runtime.Config, runtimeContractProbeStateConfigKey, contractProbeStateForRuntime(runtime, category, contractConfigured))
}

func invalidEventFieldName(err error) string {
	message := err.Error()
	for _, marker := range []string{"missing required attribute ", "missing required payload field "} {
		index := strings.Index(message, marker)
		if index < 0 {
			continue
		}
		value := strings.TrimSpace(message[index+len(marker):])
		value = strings.Trim(value, "\"'")
		if end := strings.IndexAny(value, " :"); end > 0 {
			value = value[:end]
		}
		return strings.Trim(value, "\"'")
	}
	return ""
}

func contractProbeStateForRuntime(runtime *cerebrov1.SourceRuntime, failureCategory string, contractConfigured bool) string {
	if runtime == nil || !contractConfigured {
		return "not_configured"
	}
	if strings.TrimSpace(failureCategory) != "" {
		return "failure"
	}
	if runtime.GetLastSyncedAt() == nil {
		return "unknown"
	}
	return "passing"
}

func setRuntimeConfig(config map[string]string, key string, value string) {
	if config == nil || strings.TrimSpace(key) == "" {
		return
	}
	config[key] = strings.TrimSpace(value)
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func timestampValue(value *timestamppb.Timestamp) time.Time {
	if value == nil {
		return time.Time{}
	}
	timestamp := value.AsTime()
	if timestamp.IsZero() {
		return time.Time{}
	}
	return timestamp.UTC()
}

func runtimeWatermarkLag(runtime *cerebrov1.SourceRuntime, now time.Time) (time.Time, int64, bool) {
	if runtime == nil || runtime.GetCheckpoint().GetWatermark() == nil {
		return time.Time{}, 0, false
	}
	watermark := runtime.GetCheckpoint().GetWatermark().AsTime().UTC()
	if watermark.IsZero() {
		return time.Time{}, 0, false
	}
	lag := now.UTC().Sub(watermark)
	if lag < 0 {
		lag = 0
	}
	return watermark, int64(lag.Seconds()), true
}

func (s *Service) resolveConfig(ctx context.Context, sourceID string, tenantID string, config map[string]string) (map[string]string, error) {
	return s.resolveConfigWithOptions(ctx, sourceID, tenantID, config, false)
}

func (s *Service) resolveConfigWithOptions(ctx context.Context, sourceID string, tenantID string, config map[string]string, legacyTenantlessAssumeRole bool) (map[string]string, error) {
	resolver := s.resolver
	if resolver == nil {
		return sourceRuntimeConfig(userConfig(config), sourceID, tenantID, legacyTenantlessAssumeRole), nil
	}
	resolved, err := resolver(ctx, sourceID, userConfig(config))
	if err != nil {
		return nil, err
	}
	return sourceRuntimeConfig(resolvedConfig(resolved), sourceID, tenantID, legacyTenantlessAssumeRole), nil
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
		RuntimeID:  strings.TrimSpace(filter.RuntimeID),
		RuntimeIDs: normalizedListFilterRuntimeIDs(filter),
		TenantID:   strings.TrimSpace(filter.TenantID),
		SourceID:   strings.TrimSpace(filter.SourceID),
		Limit:      filter.Limit,
	}
	if normalized.Limit == 0 {
		normalized.Limit = defaultListLimit
	}
	if normalized.Limit > maxListLimit {
		return ports.SourceRuntimeFilter{}, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidRequest, maxListLimit)
	}
	return normalized, nil
}

func normalizedListFilterRuntimeIDs(filter ports.SourceRuntimeFilter) []string {
	values := append([]string{}, filter.RuntimeIDs...)
	if strings.TrimSpace(filter.RuntimeID) != "" {
		values = append(values, filter.RuntimeID)
	}
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
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
		!sameConfig(userConfig(existing.GetConfig()), userConfig(incoming.GetConfig())) ||
		progressConfigHashChanged(existing.GetConfig(), incoming.GetConfig())
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

func boundedUint32(value int) uint32 {
	if value <= 0 {
		return 0
	}
	if value > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(value)
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
		if strings.TrimSpace(cloned.Attributes[ports.EventAttributeSourceRuntimeID]) == "" {
			cloned.Attributes[ports.EventAttributeSourceRuntimeID] = strings.TrimSpace(runtime.GetId())
		}
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

func userConfig(config map[string]string) map[string]string {
	cloned := make(map[string]string, len(config))
	for key, value := range config {
		if key == runtimeProgressConfigHashKey || sourceconfig.InternalKey(key) {
			continue
		}
		cloned[key] = value
	}
	return cloned
}

func resolvedConfig(config map[string]string) map[string]string {
	cloned := make(map[string]string, len(config))
	for key, value := range config {
		if key == runtimeProgressConfigHashKey {
			continue
		}
		cloned[key] = value
	}
	return cloned
}

func sourceRuntimeConfig(config map[string]string, sourceID string, tenantID string, legacyTenantlessAssumeRole bool) map[string]string {
	resolved := sourceconfig.WithRuntimeTenant(resolvedConfig(config), tenantID)
	if legacyTenantlessAssumeRole {
		resolved = sourceconfig.WithLegacyTenantlessAssumeRole(resolved, sourceID, tenantID)
	}
	return resolved
}

func legacyTenantlessAssumeRoleUpdate(existing *cerebrov1.SourceRuntime, incoming *cerebrov1.SourceRuntime) bool {
	if !legacyTenantlessAssumeRoleRuntime(existing) || incoming == nil {
		return false
	}
	if strings.TrimSpace(incoming.GetTenantId()) != "" {
		return false
	}
	return strings.TrimSpace(incoming.GetConfig()["role_arn"]) == strings.TrimSpace(existing.GetConfig()["role_arn"])
}

func legacyTenantlessAssumeRoleRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if runtime == nil {
		return false
	}
	return sourceconfig.LegacyTenantlessAssumeRoleConfig(runtime.GetSourceId(), runtime.GetTenantId(), runtime.GetConfig())
}

func withProgressConfigHash(config map[string]string, hash string) map[string]string {
	cloned := userConfig(config)
	cloned[runtimeProgressConfigHashKey] = hash
	return cloned
}

func configWithProgressHash(rawConfig map[string]string, resolvedConfig map[string]string) map[string]string {
	hash, ok := progressConfigHashForRuntime(rawConfig, resolvedConfig)
	if !ok {
		return userConfig(rawConfig)
	}
	return withProgressConfigHash(rawConfig, hash)
}

func refreshRuntimeProgressConfig(runtime *cerebrov1.SourceRuntime, resolvedConfig map[string]string) {
	if runtime == nil {
		return
	}
	hash, ok := progressConfigHashForRuntime(runtime.GetConfig(), resolvedConfig)
	if !ok {
		runtime.Config = userConfig(runtime.GetConfig())
		return
	}
	if runtime.GetConfig()[runtimeProgressConfigHashKey] == hash {
		return
	}
	runtime.Checkpoint = nil
	runtime.NextCursor = nil
	runtime.LastSyncedAt = nil
	runtime.Config = withProgressConfigHash(runtime.GetConfig(), hash)
}

func progressConfigHashForRuntime(rawConfig map[string]string, resolvedConfig map[string]string) (string, bool) {
	if !hasProgressConfigReferences(rawConfig, resolvedConfig) {
		return "", false
	}
	return progressConfigHash(resolvedConfig), true
}

func hasProgressConfigReferences(config map[string]string, resolvedConfig map[string]string) bool {
	for key, value := range config {
		if key == runtimeProgressConfigHashKey || sourceconfig.InternalKey(key) || progressHashSensitiveConfigKey(key) {
			continue
		}
		if sourceconfig.LiteralEnvPrefixKey(key) && resolvedConfig[key] == value {
			continue
		}
		if sourceconfig.IsSecretReference(value) {
			return true
		}
	}
	return false
}

func progressConfigHashChanged(existing map[string]string, incoming map[string]string) bool {
	incomingHash := incoming[runtimeProgressConfigHashKey]
	if incomingHash == "" {
		return false
	}
	return existing[runtimeProgressConfigHashKey] != incomingHash
}

func progressConfigHash(config map[string]string) string {
	keys := make([]string, 0, len(config))
	for key := range config {
		if key == runtimeProgressConfigHashKey || sourceconfig.InternalKey(key) || progressHashSensitiveConfigKey(key) {
			continue
		}
		keys = append(keys, key)
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

func progressHashSensitiveConfigKey(key string) bool {
	if sourceconfig.SensitiveKey(key) {
		return true
	}
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(strings.TrimSpace(key)))
	return compact == "accesskeyid"
}

func redactRuntime(runtime *cerebrov1.SourceRuntime) *cerebrov1.SourceRuntime {
	cloned := cloneRuntime(runtime)
	if cloned == nil {
		return nil
	}
	redacted := make(map[string]string, len(cloned.GetConfig()))
	for key, value := range cloned.GetConfig() {
		if key == runtimeProgressConfigHashKey || sourceconfig.InternalKey(key) {
			continue
		}
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
	if sourceconfig.SensitiveKey(key) {
		return true
	}
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(strings.TrimSpace(key)))
	return strings.Contains(compact, "accesskey") || strings.Contains(compact, "signingkey")
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

func runtimeStartCursor(runtime *cerebrov1.SourceRuntime) *cerebrov1.SourceCursor {
	if cursor := cloneCursor(runtime.GetNextCursor()); cursor != nil {
		return cursor
	}
	opaque := strings.TrimSpace(runtime.GetCheckpoint().GetCursorOpaque())
	if opaque == "" || !resumableCheckpointCursor(opaque) {
		return nil
	}
	return &cerebrov1.SourceCursor{Opaque: opaque}
}

func resumableCheckpointCursor(opaque string) bool {
	var payload struct {
		ResumableCheckpoint bool `json:"resumable_checkpoint"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(opaque)), &payload); err != nil {
		return false
	}
	return payload.ResumableCheckpoint
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
