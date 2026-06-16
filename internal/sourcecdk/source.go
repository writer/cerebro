package sourcecdk

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
)

var ErrInvalidConfig = errors.New("invalid source config")

// URN identifies an entity surfaced by a source.
type URN string

// ParseURN validates the canonical Cerebro URN format.
func ParseURN(raw string) (URN, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("urn is required")
	}
	if !strings.HasPrefix(value, "urn:cerebro:") {
		return "", fmt.Errorf("invalid cerebro urn %q", value)
	}
	parts := strings.Split(value, ":")
	if len(parts) > 3 && parts[3] == "runtime" && (len(parts) < 7 || parts[5] == "") {
		return "", fmt.Errorf("invalid cerebro urn %q", value)
	}
	if len(parts) < 5 || parts[0] != "urn" || parts[1] != "cerebro" {
		return "", fmt.Errorf("invalid cerebro urn %q", value)
	}
	if parts[len(parts)-1] == "" {
		return "", fmt.Errorf("invalid cerebro urn %q", value)
	}
	for i, part := range parts[2:] {
		if strings.TrimSpace(part) != part || (i < 3 && part == "") {
			return "", fmt.Errorf("invalid cerebro urn %q", value)
		}
	}
	return URN(value), nil
}

// String returns the raw URN string.
func (u URN) String() string {
	return string(u)
}

// Config carries source-specific static configuration.
type Config struct {
	values map[string]string
}

// NewConfig snapshots source configuration.
func NewConfig(values map[string]string) Config {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return Config{values: cloned}
}

// Lookup returns a single config value.
func (c Config) Lookup(key string) (string, bool) {
	value, ok := c.values[key]
	return value, ok
}

// Values returns a cloned map of all config entries.
func (c Config) Values() map[string]string {
	return NewConfig(c.values).values
}

// Pull is one page of source output.
type Pull struct {
	Events             []*primitives.Event
	Checkpoint         *cerebrov1.SourceCheckpoint
	NextCursor         *cerebrov1.SourceCursor
	ShortCircuitReason PullShortCircuitReason
}

// PullShortCircuitReason describes source work that intentionally produced no
// new append-log events.
type PullShortCircuitReason string

const (
	PullShortCircuitReasonScopeExcluded         PullShortCircuitReason = "scope_excluded"
	PullShortCircuitReasonResourceScopeFiltered PullShortCircuitReason = "resource_scope_filtered"
	PullShortCircuitReasonNotModified           PullShortCircuitReason = "not_modified"
	PullShortCircuitReasonCheckpointAdvanced    PullShortCircuitReason = "checkpoint_advanced"
	PullShortCircuitReasonWatermarkReached      PullShortCircuitReason = "watermark_reached"
)

// Source is the common integration contract for the rewrite.
type Source interface {
	Spec() *cerebrov1.SourceSpec
	Check(context.Context, Config) error
	Discover(context.Context, Config) ([]URN, error)
	Read(context.Context, Config, *cerebrov1.SourceCursor) (Pull, error)
}

// CheckpointAwareSource can use the last durable checkpoint while deciding how
// much remote data to fetch. Source runtimes still pass the normal page cursor
// for continuation, and provide checkpoint separately so legacy cursor formats
// do not need to carry watermark metadata.
type CheckpointAwareSource interface {
	ReadWithCheckpoint(context.Context, Config, *cerebrov1.SourceCursor, *cerebrov1.SourceCheckpoint) (Pull, error)
}

// EventContractProvider lets sources attach catalog-level per-kind validation to emitted events.
type EventContractProvider interface {
	EventContracts() []EventContract
}

// CoverageContractProvider lets sources expose machine-readable collection coverage.
type CoverageContractProvider interface {
	CoverageContract() CoverageContract
}

// Registry indexes sources by their stable identifier.
type Registry struct {
	sources map[string]Source
}

// NewRegistry constructs a source registry and rejects duplicate or invalid specs.
func NewRegistry(sources ...Source) (*Registry, error) {
	indexed := make(map[string]Source, len(sources))
	for _, source := range sources {
		if sourceIsNil(source) {
			return nil, fmt.Errorf("source is required")
		}
		spec := source.Spec()
		if spec == nil {
			return nil, fmt.Errorf("source spec is required")
		}
		rawID := spec.Id
		id := strings.TrimSpace(rawID)
		if id == "" {
			return nil, fmt.Errorf("source id is required")
		}
		if id != rawID {
			return nil, fmt.Errorf("source id %q must not have leading/trailing whitespace", rawID)
		}
		if _, exists := indexed[id]; exists {
			return nil, fmt.Errorf("duplicate source id %q", id)
		}
		source = sourceWithCatalogEventContracts(source, id)
		source = sourceWithCatalogCoverageContract(source, id)
		indexed[id] = source
	}
	return &Registry{sources: indexed}, nil
}

type catalogContractSource struct {
	Source
	contracts []EventContract
}

func (s *catalogContractSource) EventContracts() []EventContract {
	if s == nil {
		return nil
	}
	return cloneEventContracts(s.contracts)
}

func (s *catalogContractSource) ReadWithCheckpoint(ctx context.Context, cfg Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (Pull, error) {
	if s == nil || sourceIsNil(s.Source) {
		return Pull{}, fmt.Errorf("source is required")
	}
	if reader, ok := s.Source.(CheckpointAwareSource); ok {
		return reader.ReadWithCheckpoint(ctx, cfg, cursor, checkpoint)
	}
	return s.Read(ctx, cfg, cursor)
}

func sourceWithCatalogEventContracts(source Source, sourceID string) Source {
	if _, ok := source.(EventContractProvider); ok {
		return source
	}
	contracts := catalogEventContractsForSource(sourceID)
	if len(contracts) == 0 {
		return source
	}
	return &catalogContractSource{Source: source, contracts: contracts}
}

type catalogCoverageSource struct {
	Source
	coverage CoverageContract
}

func (s *catalogCoverageSource) CoverageContract() CoverageContract {
	if s == nil {
		return CoverageContract{}
	}
	return cloneCoverageContract(s.coverage)
}

func (s *catalogCoverageSource) EventContracts() []EventContract {
	if s == nil {
		return nil
	}
	provider, ok := s.Source.(EventContractProvider)
	if !ok {
		return nil
	}
	return cloneEventContracts(provider.EventContracts())
}

func (s *catalogCoverageSource) ReadWithCheckpoint(ctx context.Context, cfg Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (Pull, error) {
	if s == nil || sourceIsNil(s.Source) {
		return Pull{}, fmt.Errorf("source is required")
	}
	if reader, ok := s.Source.(CheckpointAwareSource); ok {
		return reader.ReadWithCheckpoint(ctx, cfg, cursor, checkpoint)
	}
	return s.Read(ctx, cfg, cursor)
}

func sourceWithCatalogCoverageContract(source Source, sourceID string) Source {
	if _, ok := source.(CoverageContractProvider); ok {
		return source
	}
	contract := catalogCoverageContractForSource(sourceID)
	if contract == nil {
		return source
	}
	return &catalogCoverageSource{Source: source, coverage: cloneCoverageContract(*contract)}
}

func sourceIsNil(source Source) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// Get returns a registered source by ID.
func (r *Registry) Get(id string) (Source, bool) {
	if r == nil {
		return nil, false
	}
	source, ok := r.sources[id]
	return source, ok
}

// List returns all registered source specs sorted by ID.
func (r *Registry) List() []*cerebrov1.SourceSpec {
	if r == nil {
		return nil
	}
	ids := make([]string, 0, len(r.sources))
	for id := range r.sources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	specs := make([]*cerebrov1.SourceSpec, 0, len(ids))
	for _, id := range ids {
		specs = append(specs, r.sources[id].Spec())
	}
	return specs
}

// CoverageContracts returns source coverage contracts sorted by source ID.
func (r *Registry) CoverageContracts() []CoverageContract {
	if r == nil {
		return nil
	}
	ids := make([]string, 0, len(r.sources))
	for id := range r.sources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	contracts := make([]CoverageContract, 0, len(ids))
	for _, id := range ids {
		provider, ok := r.sources[id].(CoverageContractProvider)
		if !ok {
			continue
		}
		contract := provider.CoverageContract()
		if len(contract.Dimensions) == 0 {
			continue
		}
		contracts = append(contracts, cloneCoverageContract(contract))
	}
	return contracts
}
