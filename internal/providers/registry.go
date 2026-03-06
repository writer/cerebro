package providers

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/snowflake"
	"golang.org/x/sync/errgroup"
)

// Provider interface for custom data sources beyond native scanners
type Provider interface {
	Name() string
	Type() ProviderType
	Configure(ctx context.Context, config map[string]interface{}) error
	Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error)
	Test(ctx context.Context) error
	Schema() []TableSchema
}

type ProviderType string

const (
	ProviderTypeCloud    ProviderType = "cloud"
	ProviderTypeSaaS     ProviderType = "saas"
	ProviderTypeIdentity ProviderType = "identity"
	ProviderTypeEndpoint ProviderType = "endpoint"
	ProviderTypeNetwork  ProviderType = "network"
	ProviderTypeCustom   ProviderType = "custom"
)

type SyncOptions struct {
	FullSync    bool
	Tables      []string
	Since       *time.Time
	Concurrency int
}

type SyncResult struct {
	Provider    string        `json:"provider"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
	Duration    time.Duration `json:"duration"`
	Tables      []TableResult `json:"tables"`
	TotalRows   int64         `json:"total_rows"`
	Errors      []string      `json:"errors,omitempty"`
}

type TableResult struct {
	Name     string `json:"name"`
	Rows     int64  `json:"rows"`
	Inserted int64  `json:"inserted"`
	Updated  int64  `json:"updated"`
	Deleted  int64  `json:"deleted"`
	Error    string `json:"error,omitempty"`
}

type TableSchema struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Columns     []ColumnSchema `json:"columns"`
	PrimaryKey  []string       `json:"primary_key"`
}

type ColumnSchema struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
}

// Registry manages provider registration and lifecycle
type Registry struct {
	providers map[string]Provider
	configs   map[string]map[string]interface{}
	mu        sync.RWMutex
}

var ErrProviderNotFound = errors.New("provider not found")

func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
		configs:   make(map[string]map[string]interface{}),
	}
}

func (r *Registry) Register(provider Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[provider.Name()] = provider
}

func (r *Registry) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

func (r *Registry) List() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	providers := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		providers = append(providers, p)
	}
	return providers
}

func (r *Registry) Configure(ctx context.Context, name string, config map[string]interface{}) error {
	r.mu.Lock()
	provider, ok := r.providers[name]
	if !ok {
		r.mu.Unlock()
		return ErrProviderNotFound
	}
	r.configs[name] = config
	r.mu.Unlock()

	return provider.Configure(ctx, config)
}

func (r *Registry) SyncAll(ctx context.Context, opts SyncOptions) ([]*SyncResult, error) {
	r.mu.RLock()
	providers := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		providers = append(providers, p)
	}
	r.mu.RUnlock()

	results := make([]*SyncResult, len(providers))
	var mu sync.Mutex
	var errs []error
	var group errgroup.Group
	limit := opts.Concurrency
	if limit <= 0 {
		limit = 4
	}
	group.SetLimit(limit)

	for i, p := range providers {
		idx := i
		provider := p
		group.Go(func() error {
			result, err := provider.Sync(ctx, opts)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				// Capture partial result if available, otherwise create error result
				if result != nil {
					result.Errors = append(result.Errors, err.Error())
					results[idx] = result
				} else {
					results[idx] = &SyncResult{
						Provider: provider.Name(),
						Errors:   []string{err.Error()},
					}
				}
			} else {
				results[idx] = result
			}
			return nil
		})
	}

	_ = group.Wait()
	return results, errors.Join(errs...)
}

// BaseProvider provides common functionality for custom providers
type BaseProvider struct {
	name       string
	provType   ProviderType
	config     map[string]interface{}
	configured bool
	snowflake  *snowflake.Client
	mu         sync.RWMutex
}

func NewBaseProvider(name string, provType ProviderType) *BaseProvider {
	return &BaseProvider{
		name:     name,
		provType: provType,
	}
}

func (b *BaseProvider) Name() string {
	return b.name
}

func (b *BaseProvider) Type() ProviderType {
	return b.provType
}

func (b *BaseProvider) Configure(ctx context.Context, config map[string]interface{}) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.config = config
	b.configured = true
	return nil
}

func (b *BaseProvider) GetConfig(key string) interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.config[key]
}

func (b *BaseProvider) GetConfigString(key string) string {
	if v := b.GetConfig(key); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (b *BaseProvider) IsConfigured() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.configured
}
