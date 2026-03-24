package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptunedata"
	neptunedatatypes "github.com/aws/aws-sdk-go-v2/service/neptunedata/types"
)

const (
	defaultNeptuneDataExecutorPoolSize                = 4
	defaultNeptuneDataExecutorPoolHealthCheckInterval = 30 * time.Second
	defaultNeptuneDataExecutorPoolHealthCheckTimeout  = 5 * time.Second
	defaultNeptuneDataExecutorPoolMaxClientLifetime   = 30 * time.Minute
	defaultNeptuneDataExecutorPoolDrainTimeout        = 15 * time.Second
	neptuneConnectionPoolHealthcheckQuery             = "RETURN 1"
)

var errNeptuneConnectionPoolDraining = errors.New("neptune connection pool draining")

// NeptuneDataClientFactory builds one Neptune data API client for pooled use.
type NeptuneDataClientFactory func() (NeptuneDataClient, error)

// NeptuneDataExecutorPoolConfig controls pooled Neptune client behavior.
type NeptuneDataExecutorPoolConfig struct {
	Size                int
	HealthCheckInterval time.Duration
	HealthCheckTimeout  time.Duration
	MaxClientLifetime   time.Duration
	MaxClientUses       int
	DrainTimeout        time.Duration
}

// DefaultNeptuneDataExecutorPoolConfig returns normalized defaults for Neptune pooling.
func DefaultNeptuneDataExecutorPoolConfig() NeptuneDataExecutorPoolConfig {
	return NeptuneDataExecutorPoolConfig{
		Size:                defaultNeptuneDataExecutorPoolSize,
		HealthCheckInterval: defaultNeptuneDataExecutorPoolHealthCheckInterval,
		HealthCheckTimeout:  defaultNeptuneDataExecutorPoolHealthCheckTimeout,
		MaxClientLifetime:   defaultNeptuneDataExecutorPoolMaxClientLifetime,
		DrainTimeout:        defaultNeptuneDataExecutorPoolDrainTimeout,
	}
}

func normalizeNeptuneDataExecutorPoolConfig(cfg NeptuneDataExecutorPoolConfig) NeptuneDataExecutorPoolConfig {
	defaults := DefaultNeptuneDataExecutorPoolConfig()
	if cfg.Size <= 0 {
		cfg.Size = defaults.Size
	}
	if cfg.HealthCheckInterval < 0 {
		cfg.HealthCheckInterval = 0
	}
	if cfg.HealthCheckInterval > 0 && cfg.HealthCheckTimeout <= 0 {
		cfg.HealthCheckTimeout = defaults.HealthCheckTimeout
	}
	if cfg.MaxClientLifetime < 0 {
		cfg.MaxClientLifetime = 0
	}
	if cfg.MaxClientLifetime == 0 {
		cfg.MaxClientLifetime = defaults.MaxClientLifetime
	}
	if cfg.MaxClientUses < 0 {
		cfg.MaxClientUses = 0
	}
	if cfg.DrainTimeout <= 0 {
		cfg.DrainTimeout = defaults.DrainTimeout
	}
	return cfg
}

type pooledNeptuneDataExecutor struct {
	factory NeptuneDataClientFactory
	config  NeptuneDataExecutorPoolConfig
	now     func() time.Time

	mu            sync.Mutex
	slots         []pooledNeptuneClientSlot
	inflight      int
	draining      bool
	drainedCh     chan struct{}
	drainedClosed bool

	available chan int
	drainCh   chan struct{}

	healthStop chan struct{}
	healthDone chan struct{}

	closeOnce sync.Once
	closeErr  error
}

type pooledNeptuneClientSlot struct {
	client     neptuneDataClient
	createdAt  time.Time
	lastUsedAt time.Time
	uses       int
	busy       bool
}

// NewPooledNeptuneDataExecutor creates a pooled Neptune executor with health checking and graceful drain behavior.
func NewPooledNeptuneDataExecutor(factory NeptuneDataClientFactory, cfg NeptuneDataExecutorPoolConfig) (*pooledNeptuneDataExecutor, error) {
	if factory == nil {
		return nil, fmt.Errorf("neptune client factory is required")
	}
	cfg = normalizeNeptuneDataExecutorPoolConfig(cfg)
	exec := &pooledNeptuneDataExecutor{
		factory:    factory,
		config:     cfg,
		now:        func() time.Time { return time.Now().UTC() },
		slots:      make([]pooledNeptuneClientSlot, cfg.Size),
		drainedCh:  make(chan struct{}),
		available:  make(chan int, cfg.Size),
		drainCh:    make(chan struct{}),
		healthStop: make(chan struct{}),
		healthDone: make(chan struct{}),
	}
	for i := 0; i < cfg.Size; i++ {
		exec.available <- i
	}
	if cfg.HealthCheckInterval > 0 {
		go exec.healthLoop()
	} else {
		close(exec.healthDone)
	}
	return exec, nil
}

func (e *pooledNeptuneDataExecutor) ExecuteOpenCypher(ctx context.Context, query string, params map[string]any) (any, error) {
	if e == nil {
		return nil, ErrStoreUnavailable
	}
	borrow, err := e.borrow(ctx)
	if err != nil {
		return nil, err
	}
	defer e.releaseBorrow(borrow.index, true)

	input := &neptunedata.ExecuteOpenCypherQueryInput{
		OpenCypherQuery: aws.String(query),
	}
	if len(params) > 0 {
		encoded, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal neptune parameters: %w", err)
		}
		input.Parameters = aws.String(string(encoded))
	}
	output, err := borrow.client.ExecuteOpenCypherQuery(ctx, input)
	if err != nil {
		return nil, err
	}
	if output == nil {
		return nil, nil
	}
	return output.Results, nil
}

func (e *pooledNeptuneDataExecutor) ExecuteOpenCypherExplain(ctx context.Context, query string, mode NeptuneExplainMode, params map[string]any) ([]byte, error) {
	if e == nil {
		return nil, ErrStoreUnavailable
	}
	borrow, err := e.borrow(ctx)
	if err != nil {
		return nil, err
	}
	defer e.releaseBorrow(borrow.index, true)

	input := &neptunedata.ExecuteOpenCypherExplainQueryInput{
		OpenCypherQuery: aws.String(strings.TrimSpace(query)),
		ExplainMode:     neptunedatatypes.OpenCypherExplainMode(mode),
	}
	if len(params) > 0 {
		encoded, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal neptune explain parameters: %w", err)
		}
		input.Parameters = aws.String(string(encoded))
	}
	output, err := borrow.client.ExecuteOpenCypherExplainQuery(ctx, input)
	if err != nil {
		return nil, err
	}
	if output == nil {
		return nil, nil
	}
	return output.Results, nil
}

func (e *pooledNeptuneDataExecutor) Close() error {
	if e == nil {
		return nil
	}
	e.closeOnce.Do(func() {
		e.closeErr = e.close()
	})
	return e.closeErr
}

func (e *pooledNeptuneDataExecutor) close() error {
	e.mu.Lock()
	if !e.draining {
		e.draining = true
		close(e.drainCh)
	}
	if e.inflight == 0 && !e.drainedClosed {
		close(e.drainedCh)
		e.drainedClosed = true
	}
	e.mu.Unlock()

	close(e.healthStop)
	<-e.healthDone

	var errs []error
	errs = append(errs, closeNeptuneClients(e.detachIdleClients())...)

	if e.config.DrainTimeout > 0 {
		timer := time.NewTimer(e.config.DrainTimeout)
		defer timer.Stop()
		select {
		case <-e.drainedCh:
		case <-timer.C:
			return errors.Join(append(errs, fmt.Errorf("timed out draining neptune connection pool after %s", e.config.DrainTimeout))...)
		}
	} else {
		<-e.drainedCh
	}

	errs = append(errs, closeNeptuneClients(e.detachAllClients())...)
	return errors.Join(errs...)
}

type pooledNeptuneBorrow struct {
	index  int
	client neptuneDataClient
}

func (e *pooledNeptuneDataExecutor) borrow(ctx context.Context) (*pooledNeptuneBorrow, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case <-e.drainCh:
		return nil, errors.Join(ErrStoreUnavailable, errNeptuneConnectionPoolDraining)
	case <-ctx.Done():
		return nil, ctx.Err()
	case index := <-e.available:
		e.mu.Lock()
		if e.draining {
			e.mu.Unlock()
			return nil, errors.Join(ErrStoreUnavailable, errNeptuneConnectionPoolDraining)
		}
		slot := &e.slots[index]
		slot.busy = true
		e.inflight++
		client := slot.client
		replace := client == nil || e.shouldRecycleLocked(slot)
		if replace {
			slot.client = nil
			slot.createdAt = time.Time{}
			slot.lastUsedAt = time.Time{}
			slot.uses = 0
		}
		e.mu.Unlock()

		if replace {
			if client != nil {
				_ = closeNeptuneClient(client)
			}
			newClient, err := e.factory()
			if err != nil {
				e.releaseBorrow(index, false)
				return nil, err
			}
			client = newClient
			e.mu.Lock()
			slot = &e.slots[index]
			slot.client = newClient
			slot.createdAt = e.now()
			slot.lastUsedAt = time.Time{}
			slot.uses = 0
			e.mu.Unlock()
		}

		return &pooledNeptuneBorrow{index: index, client: client}, nil
	}
}

func (e *pooledNeptuneDataExecutor) releaseBorrow(index int, countUse bool) {
	var clientToClose neptuneDataClient
	e.mu.Lock()
	slot := &e.slots[index]
	if countUse && slot.client != nil {
		slot.uses++
		slot.lastUsedAt = e.now()
	}
	if slot.client != nil && (e.draining || e.shouldRecycleLocked(slot)) {
		clientToClose = slot.client
		slot.client = nil
		slot.createdAt = time.Time{}
		slot.lastUsedAt = time.Time{}
		slot.uses = 0
	}
	slot.busy = false
	e.inflight--
	if e.draining && e.inflight == 0 && !e.drainedClosed {
		close(e.drainedCh)
		e.drainedClosed = true
	}
	shouldReturn := !e.draining
	e.mu.Unlock()

	if clientToClose != nil {
		_ = closeNeptuneClient(clientToClose)
	}
	if shouldReturn {
		e.available <- index
	}
}

func (e *pooledNeptuneDataExecutor) shouldRecycleLocked(slot *pooledNeptuneClientSlot) bool {
	if slot == nil || slot.client == nil {
		return true
	}
	if e.config.MaxClientUses > 0 && slot.uses >= e.config.MaxClientUses {
		return true
	}
	if e.config.MaxClientLifetime > 0 && !slot.createdAt.IsZero() && e.now().Sub(slot.createdAt) >= e.config.MaxClientLifetime {
		return true
	}
	return false
}

func (e *pooledNeptuneDataExecutor) healthLoop() {
	ticker := time.NewTicker(e.config.HealthCheckInterval)
	defer func() {
		ticker.Stop()
		close(e.healthDone)
	}()

	for {
		select {
		case <-e.healthStop:
			return
		case <-ticker.C:
			e.runHealthChecks()
		}
	}
}

func (e *pooledNeptuneDataExecutor) runHealthChecks() {
	count := len(e.available)
	for i := 0; i < count; i++ {
		select {
		case <-e.healthStop:
			return
		case index := <-e.available:
			e.healthCheckSlot(index)
		default:
			return
		}
	}
}

func (e *pooledNeptuneDataExecutor) healthCheckSlot(index int) {
	e.mu.Lock()
	if e.draining {
		e.mu.Unlock()
		return
	}
	slot := &e.slots[index]
	slot.busy = true
	client := slot.client
	needsReplacement := client == nil || e.shouldRecycleLocked(slot)
	if needsReplacement {
		slot.client = nil
		slot.createdAt = time.Time{}
		slot.lastUsedAt = time.Time{}
		slot.uses = 0
	}
	e.mu.Unlock()

	if needsReplacement && client != nil {
		_ = closeNeptuneClient(client)
		client = nil
	}
	if client == nil {
		replacement, err := e.factory()
		if err == nil {
			client = replacement
			e.mu.Lock()
			slot = &e.slots[index]
			slot.client = replacement
			slot.createdAt = e.now()
			slot.lastUsedAt = time.Time{}
			slot.uses = 0
			e.mu.Unlock()
		}
	}
	if client != nil {
		ctx := context.Background()
		cancel := func() {}
		if e.config.HealthCheckTimeout > 0 {
			ctx, cancel = context.WithTimeout(ctx, e.config.HealthCheckTimeout)
		}
		_, err := client.ExecuteOpenCypherQuery(ctx, &neptunedata.ExecuteOpenCypherQueryInput{
			OpenCypherQuery: aws.String(neptuneConnectionPoolHealthcheckQuery),
		})
		cancel()
		if err != nil {
			_ = closeNeptuneClient(client)
			client = nil
			e.mu.Lock()
			slot = &e.slots[index]
			slot.client = nil
			slot.createdAt = time.Time{}
			slot.lastUsedAt = time.Time{}
			slot.uses = 0
			e.mu.Unlock()

			replacement, replErr := e.factory()
			if replErr == nil {
				client = replacement
				e.mu.Lock()
				slot = &e.slots[index]
				slot.client = replacement
				slot.createdAt = e.now()
				slot.lastUsedAt = time.Time{}
				slot.uses = 0
				e.mu.Unlock()
			}
		}
	}

	e.mu.Lock()
	slot = &e.slots[index]
	slot.busy = false
	shouldReturn := !e.draining
	e.mu.Unlock()
	if shouldReturn {
		e.available <- index
	}
}

func (e *pooledNeptuneDataExecutor) detachIdleClients() []neptuneDataClient {
	e.mu.Lock()
	defer e.mu.Unlock()
	clients := make([]neptuneDataClient, 0)
	for i := range e.slots {
		if e.slots[i].busy || e.slots[i].client == nil {
			continue
		}
		clients = append(clients, e.slots[i].client)
		e.slots[i].client = nil
		e.slots[i].createdAt = time.Time{}
		e.slots[i].lastUsedAt = time.Time{}
		e.slots[i].uses = 0
	}
	return clients
}

func (e *pooledNeptuneDataExecutor) detachAllClients() []neptuneDataClient {
	e.mu.Lock()
	defer e.mu.Unlock()
	clients := make([]neptuneDataClient, 0)
	for i := range e.slots {
		if e.slots[i].client == nil {
			continue
		}
		clients = append(clients, e.slots[i].client)
		e.slots[i].client = nil
		e.slots[i].createdAt = time.Time{}
		e.slots[i].lastUsedAt = time.Time{}
		e.slots[i].uses = 0
	}
	return clients
}

func closeNeptuneClients(clients []neptuneDataClient) []error {
	errs := make([]error, 0)
	for _, client := range clients {
		if client == nil {
			continue
		}
		if err := closeNeptuneClient(client); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func closeNeptuneClient(client neptuneDataClient) error {
	if closer, ok := client.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
