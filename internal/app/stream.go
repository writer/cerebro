package app

import (
	"context"
	"log/slog"
	"time"

	appstream "github.com/writer/cerebro/internal/app/stream"
	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/health"
)

func (a *App) StreamRuntime() *appstream.Runtime {
	return a.streamRuntime()
}

func (a *App) streamRuntime() *appstream.Runtime {
	if a == nil {
		return nil
	}
	if a.Stream == nil {
		a.Stream = a.newStreamRuntime()
	}
	return a.Stream
}

func (a *App) newStreamRuntime() *appstream.Runtime {
	if a == nil {
		return nil
	}
	return appstream.NewRuntime(appstream.Dependencies{
		Logger: func() *slog.Logger {
			if a == nil {
				return nil
			}
			return a.Logger
		},
		Config: func() *appstream.Config {
			return a.streamConfig()
		},
		HealthRegistry: func() *health.Registry {
			if a == nil {
				return nil
			}
			return a.Health
		},
		GraphWriterLeaseAllowsWrites: func() bool {
			if a == nil {
				return true
			}
			return a.graphWriterLeaseAllowsWrites()
		},
		GraphWriterLeaseStatus: func() appstream.LeaseStatus {
			if a == nil {
				return appstream.LeaseStatus{}
			}
			status := a.GraphWriterLeaseStatusSnapshot()
			return appstream.LeaseStatus{Role: string(status.Role), LeaseHolderID: status.LeaseHolderID}
		},
		GraphBuildLastAt: func() time.Time {
			if a == nil {
				return time.Time{}
			}
			return a.GraphBuildSnapshot().LastBuildAt
		},
		WaitForSecurityGraphReady:       a.waitForSecurityGraphReady,
		CurrentSecurityGraph:            a.CurrentSecurityGraph,
		MutateSecurityGraphMaybe:        a.MutateSecurityGraphMaybe,
		QueueEventCorrelationRefresh:    a.queueEventCorrelationRefresh,
		InitEventCorrelationRefreshLoop: a.initEventCorrelationRefreshLoop,
		ExecutionStoreForPath:           a.executionStoreForPath,
		HandleAuditMutationCloudEvent:   a.handleAuditMutationCloudEvent,
	})
}

func (a *App) streamConfig() *appstream.Config {
	if a == nil || a.Config == nil {
		return nil
	}
	return &appstream.Config{
		GraphWriterLeaseName:                a.Config.GraphWriterLeaseName,
		NATSJetStreamURLs:                   append([]string(nil), a.Config.NATSJetStreamURLs...),
		NATSJetStreamConnectTimeout:         a.Config.NATSJetStreamConnectTimeout,
		NATSJetStreamAuthMode:               a.Config.NATSJetStreamAuthMode,
		NATSJetStreamUsername:               a.Config.NATSJetStreamUsername,
		NATSJetStreamPassword:               a.Config.NATSJetStreamPassword,
		NATSJetStreamNKeySeed:               a.Config.NATSJetStreamNKeySeed,
		NATSJetStreamUserJWT:                a.Config.NATSJetStreamUserJWT,
		NATSJetStreamTLSEnabled:             a.Config.NATSJetStreamTLSEnabled,
		NATSJetStreamTLSCAFile:              a.Config.NATSJetStreamTLSCAFile,
		NATSJetStreamTLSCertFile:            a.Config.NATSJetStreamTLSCertFile,
		NATSJetStreamTLSKeyFile:             a.Config.NATSJetStreamTLSKeyFile,
		NATSJetStreamTLSServerName:          a.Config.NATSJetStreamTLSServerName,
		NATSJetStreamTLSInsecure:            a.Config.NATSJetStreamTLSInsecure,
		NATSConsumerEnabled:                 a.Config.NATSConsumerEnabled,
		NATSConsumerStream:                  a.Config.NATSConsumerStream,
		NATSConsumerSubjects:                append([]string(nil), a.Config.NATSConsumerSubjects...),
		NATSConsumerDurable:                 a.Config.NATSConsumerDurable,
		NATSConsumerBatchSize:               a.Config.NATSConsumerBatchSize,
		NATSConsumerAckWait:                 a.Config.NATSConsumerAckWait,
		NATSConsumerFetchTimeout:            a.Config.NATSConsumerFetchTimeout,
		NATSConsumerInProgressInterval:      a.Config.NATSConsumerInProgressInterval,
		NATSConsumerDeadLetterPath:          a.Config.NATSConsumerDeadLetterPath,
		NATSConsumerDedupEnabled:            a.Config.NATSConsumerDedupEnabled,
		NATSConsumerDedupStateFile:          a.Config.NATSConsumerDedupStateFile,
		NATSConsumerDedupTTL:                a.Config.NATSConsumerDedupTTL,
		NATSConsumerDedupMaxRecords:         a.Config.NATSConsumerDedupMaxRecords,
		NATSConsumerDropHealthLookback:      a.Config.NATSConsumerDropHealthLookback,
		NATSConsumerDropHealthThreshold:     a.Config.NATSConsumerDropHealthThreshold,
		NATSConsumerGraphStalenessThreshold: a.Config.NATSConsumerGraphStalenessThreshold,
		GraphEventMapperValidationMode:      a.Config.GraphEventMapperValidationMode,
		GraphEventMapperDeadLetterPath:      a.Config.GraphEventMapperDeadLetterPath,
	}
}

func (a *App) CurrentTapEventMapper() *graphingest.Mapper {
	if runtime := a.streamRuntime(); runtime != nil {
		return runtime.Mapper()
	}
	return nil
}

func (a *App) currentTapConsumer() *events.Consumer {
	if runtime := a.streamRuntime(); runtime != nil {
		return runtime.Consumer()
	}
	return nil
}

func (a *App) handleGraphCloudEvent(ctx context.Context, evt events.CloudEvent) error {
	if runtime := a.streamRuntime(); runtime != nil {
		return runtime.HandleGraphCloudEvent(ctx, evt)
	}
	return nil
}

func (a *App) handleTapCloudEvent(ctx context.Context, evt events.CloudEvent) error {
	if runtime := a.streamRuntime(); runtime != nil {
		return runtime.HandleTapCloudEvent(ctx, evt)
	}
	return nil
}

func (a *App) tapEventMapper() (*graphingest.Mapper, error) {
	if runtime := a.streamRuntime(); runtime != nil {
		return runtime.TapEventMapper()
	}
	return nil, nil
}

func (a *App) resolveTapMappingIdentity(raw string, evt events.CloudEvent) string {
	if runtime := a.streamRuntime(); runtime != nil {
		return runtime.ResolveTapMappingIdentity(raw, evt)
	}
	return ""
}

func (a *App) withTapResolveGraph(securityGraph *graph.Graph, fn func() error) error {
	if runtime := a.streamRuntime(); runtime != nil {
		return runtime.WithTapResolveGraph(securityGraph, fn)
	}
	if fn == nil {
		return nil
	}
	return fn()
}

func (a *App) currentTapResolveGraph() *graph.Graph {
	if runtime := a.streamRuntime(); runtime != nil {
		return runtime.CurrentTapResolveGraph()
	}
	return nil
}

func (a *App) handleTapSchemaEvent(eventType string, evt events.CloudEvent) error {
	if runtime := a.streamRuntime(); runtime != nil {
		return runtime.HandleTapSchemaEvent(eventType, evt)
	}
	return nil
}

func (a *App) initTapGraphConsumer(ctx context.Context) {
	if runtime := a.streamRuntime(); runtime != nil {
		runtime.InitTapGraphConsumer(ctx)
	}
}

func (a *App) startTapGraphConsumer(ctx context.Context) {
	if runtime := a.streamRuntime(); runtime != nil {
		runtime.StartTapGraphConsumer(ctx)
	}
}

func (a *App) stopTapGraphConsumer(ctx context.Context) error {
	if runtime := a.streamRuntime(); runtime != nil {
		return runtime.StopTapGraphConsumer(ctx)
	}
	return nil
}

func (a *App) tapGraphConsumerSubjects() []string {
	if runtime := a.streamRuntime(); runtime != nil {
		return runtime.TapGraphConsumerSubjects()
	}
	return nil
}

func (a *App) tapGraphConsumerDurable() string {
	if runtime := a.streamRuntime(); runtime != nil {
		return runtime.TapGraphConsumerDurable()
	}
	return ""
}

func (a *App) ensureSecurityGraph() *graph.Graph {
	if a == nil {
		return nil
	}
	if !a.retainHotSecurityGraph() {
		return nil
	}

	a.securityGraphInitMu.Lock()
	defer a.securityGraphInitMu.Unlock()

	if a.SecurityGraph == nil {
		a.SecurityGraph = graph.New()
		a.configureGraphRuntimeBehavior(a.SecurityGraph)
	}
	return a.SecurityGraph
}

func (a *App) waitForSecurityGraphReady(ctx context.Context) error {
	if a == nil || a.graphReady == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-a.graphReady:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
