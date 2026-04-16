package stream

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/health"
)

type Config struct {
	GraphWriterLeaseName                string
	NATSJetStreamURLs                   []string
	NATSJetStreamConnectTimeout         time.Duration
	NATSJetStreamAuthMode               string
	NATSJetStreamUsername               string
	NATSJetStreamPassword               string
	NATSJetStreamNKeySeed               string
	NATSJetStreamUserJWT                string
	NATSJetStreamTLSEnabled             bool
	NATSJetStreamTLSCAFile              string
	NATSJetStreamTLSCertFile            string
	NATSJetStreamTLSKeyFile             string
	NATSJetStreamTLSServerName          string
	NATSJetStreamTLSInsecure            bool
	NATSConsumerEnabled                 bool
	NATSConsumerStream                  string
	NATSConsumerSubjects                []string
	NATSConsumerDurable                 string
	NATSConsumerBatchSize               int
	NATSConsumerAckWait                 time.Duration
	NATSConsumerFetchTimeout            time.Duration
	NATSConsumerInProgressInterval      time.Duration
	NATSConsumerDeadLetterPath          string
	NATSConsumerDedupEnabled            bool
	NATSConsumerDedupStateFile          string
	NATSConsumerDedupTTL                time.Duration
	NATSConsumerDedupMaxRecords         int
	NATSConsumerDropHealthLookback      time.Duration
	NATSConsumerDropHealthThreshold     int
	NATSConsumerGraphStalenessThreshold time.Duration
	GraphEventMapperValidationMode      string
	GraphEventMapperDeadLetterPath      string
}

type LeaseStatus struct {
	Role          string
	LeaseHolderID string
}

type Dependencies struct {
	Logger                          func() *slog.Logger
	Config                          func() *Config
	HealthRegistry                  func() *health.Registry
	GraphWriterLeaseAllowsWrites    func() bool
	GraphWriterLeaseStatus          func() LeaseStatus
	GraphBuildLastAt                func() time.Time
	WaitForSecurityGraphReady       func(context.Context) error
	CurrentSecurityGraph            func() *graph.Graph
	MutateSecurityGraphMaybe        func(context.Context, func(*graph.Graph) (bool, error)) (*graph.Graph, error)
	QueueEventCorrelationRefresh    func(string)
	InitEventCorrelationRefreshLoop func(context.Context)
	ExecutionStoreForPath           func(string) executionstore.Store
	HandleAuditMutationCloudEvent   func(context.Context, events.CloudEvent) error
}

type Runtime struct {
	deps Dependencies

	mapperMu          sync.Mutex
	mapper            *graphingest.Mapper
	mapperErr         error
	mapperInitialized bool

	resolveGraphMu sync.RWMutex
	resolveGraph   *graph.Graph

	consumerMu       sync.Mutex
	consumer         *events.Consumer
	consumerDurable  string
	consumerSubjects []string
}

func NewRuntime(deps Dependencies) *Runtime {
	return &Runtime{deps: deps}
}

func (r *Runtime) logger() *slog.Logger {
	if r == nil || r.deps.Logger == nil {
		return nil
	}
	return r.deps.Logger()
}

func (r *Runtime) config() *Config {
	if r == nil || r.deps.Config == nil {
		return nil
	}
	return r.deps.Config()
}

func (r *Runtime) healthRegistry() *health.Registry {
	if r == nil || r.deps.HealthRegistry == nil {
		return nil
	}
	return r.deps.HealthRegistry()
}

func (r *Runtime) graphWriterLeaseAllowsWrites() bool {
	if r == nil || r.deps.GraphWriterLeaseAllowsWrites == nil {
		return true
	}
	return r.deps.GraphWriterLeaseAllowsWrites()
}

func (r *Runtime) graphWriterLeaseStatus() LeaseStatus {
	if r == nil || r.deps.GraphWriterLeaseStatus == nil {
		return LeaseStatus{}
	}
	return r.deps.GraphWriterLeaseStatus()
}

func (r *Runtime) graphBuildLastAt() time.Time {
	if r == nil || r.deps.GraphBuildLastAt == nil {
		return time.Time{}
	}
	return r.deps.GraphBuildLastAt()
}

func (r *Runtime) waitForSecurityGraphReady(ctx context.Context) error {
	if r == nil || r.deps.WaitForSecurityGraphReady == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return r.deps.WaitForSecurityGraphReady(ctx)
}

func (r *Runtime) currentSecurityGraph() *graph.Graph {
	if r == nil || r.deps.CurrentSecurityGraph == nil {
		return nil
	}
	return r.deps.CurrentSecurityGraph()
}

func (r *Runtime) mutateSecurityGraphMaybe(ctx context.Context, mutate func(*graph.Graph) (bool, error)) (*graph.Graph, error) {
	if r == nil || r.deps.MutateSecurityGraphMaybe == nil {
		return nil, fmt.Errorf("stream runtime mutate callback is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return r.deps.MutateSecurityGraphMaybe(ctx, mutate)
}

func (r *Runtime) queueEventCorrelationRefresh(reason string) {
	if r == nil || r.deps.QueueEventCorrelationRefresh == nil {
		return
	}
	r.deps.QueueEventCorrelationRefresh(strings.TrimSpace(reason))
}

func (r *Runtime) initEventCorrelationRefreshLoop(ctx context.Context) {
	if r == nil || r.deps.InitEventCorrelationRefreshLoop == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.deps.InitEventCorrelationRefreshLoop(ctx)
}

func (r *Runtime) executionStoreForPath(path string) executionstore.Store {
	if r == nil || r.deps.ExecutionStoreForPath == nil {
		return nil
	}
	return r.deps.ExecutionStoreForPath(path)
}

func (r *Runtime) handleAuditMutationCloudEvent(ctx context.Context, evt events.CloudEvent) error {
	if r == nil || r.deps.HandleAuditMutationCloudEvent == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return r.deps.HandleAuditMutationCloudEvent(ctx, evt)
}

func (r *Runtime) Consumer() *events.Consumer {
	if r == nil {
		return nil
	}
	r.consumerMu.Lock()
	defer r.consumerMu.Unlock()
	return r.consumer
}

func (r *Runtime) Mapper() *graphingest.Mapper {
	if r == nil {
		return nil
	}
	r.mapperMu.Lock()
	defer r.mapperMu.Unlock()
	return r.mapper
}

func (r *Runtime) SetMapper(mapper *graphingest.Mapper) {
	if r == nil {
		return
	}
	r.mapperMu.Lock()
	defer r.mapperMu.Unlock()
	r.mapper = mapper
	r.mapperErr = nil
	r.mapperInitialized = true
}
