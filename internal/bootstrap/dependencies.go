package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	appendlogjetstream "github.com/writer/cerebro/internal/appendlog/jetstream"
	appendlogrecovery "github.com/writer/cerebro/internal/appendlog/recovery"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphagent"
	graphstoreneo4j "github.com/writer/cerebro/internal/graphstore/neo4j"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/querycache"
	statestorepostgres "github.com/writer/cerebro/internal/statestore/postgres"
)

const dependencyPingTimeout = 15 * time.Second

type closer func(context.Context) error

// OpenDependencies dials the configured append-log and current-state drivers.
func OpenDependencies(ctx context.Context, cfg config.Config) (Dependencies, func() error, error) {
	var (
		deps    Dependencies
		closers []closer
	)
	closeAll := func() error {
		var errs []error
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dependencyPingTimeout)
		defer cancel()
		for i := len(closers) - 1; i >= 0; i-- {
			if err := closers[i](closeCtx); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	fail := func(err error) (Dependencies, func() error, error) {
		_ = closeAll()
		return Dependencies{}, func() error { return nil }, err
	}
	if cfg.AppendLog.Driver == config.AppendLogDriverJetStream {
		appendLog, err := appendlogjetstream.Open(cfg.AppendLog)
		if err != nil {
			return fail(fmt.Errorf("open append log: %w", err))
		}
		deps.AppendLog = appendLog
		closers = append(closers, func(context.Context) error {
			return appendLog.Close()
		})
	}
	if cfg.StateStore.Driver == config.StateStoreDriverPostgres {
		stateStore, err := statestorepostgres.Open(cfg.StateStore)
		if err != nil {
			return fail(fmt.Errorf("open state store: %w", err))
		}
		deps.StateStore = stateStore
		closers = append(closers, func(context.Context) error {
			return stateStore.Close()
		})
	}
	if cfg.AppendLog.JetStreamRuntimeIndexEnabled {
		if index, ok := deps.StateStore.(ports.RuntimeReplayIndex); ok && !isNilInterface(index) {
			if appendLog, ok := deps.AppendLog.(*appendlogjetstream.Log); ok && appendLog != nil {
				appendLog.SetRuntimeReplayIndex(index)
			}
		}
	}
	if store, ok := deps.StateStore.(ports.AppendLogDeadLetterStore); ok && !isNilInterface(store) {
		deps.AppendLog = appendlogrecovery.Wrap(deps.AppendLog, store)
	}
	switch cfg.GraphStore.Driver {
	case "":
	case config.GraphStoreDriverNeo4j:
		graphStore, err := graphstoreneo4j.Open(cfg.GraphStore)
		if err != nil {
			return fail(fmt.Errorf("open graph store: %w", err))
		}
		deps.GraphStore = graphStore
		closers = append(closers, func(closeCtx context.Context) error {
			return graphStore.CloseContext(closeCtx)
		})
	default:
		return fail(fmt.Errorf("unsupported graph store driver %q", cfg.GraphStore.Driver))
	}
	if err := pingDependency(ctx, "append log", deps.AppendLog); err != nil {
		return fail(err)
	}
	if err := pingDependency(ctx, "state store", deps.StateStore); err != nil {
		return fail(err)
	}
	if err := pingDependency(ctx, "graph store", deps.GraphStore); err != nil {
		return fail(err)
	}
	switch cfg.Cache.Driver {
	case "", config.CacheDriverOff:
	case config.CacheDriverMemory:
		deps.QueryCache = querycache.NewMemory(querycache.Options{
			Namespace:       cfg.Cache.Namespace,
			MaxPayloadBytes: cfg.Cache.MaxPayloadBytes,
		})
	case config.CacheDriverRedis, config.CacheDriverValkey:
		cache, err := querycache.OpenRedis(cfg.Cache.URL, querycache.Options{
			Namespace:       cfg.Cache.Namespace,
			MaxPayloadBytes: cfg.Cache.MaxPayloadBytes,
		})
		if err != nil {
			return fail(fmt.Errorf("open query cache: %w", err))
		}
		deps.QueryCache = cache
		closers = append(closers, func(closeCtx context.Context) error {
			return cache.Close(closeCtx)
		})
	default:
		return fail(fmt.Errorf("unsupported cache driver %q", cfg.Cache.Driver))
	}
	if err := pingDependency(ctx, "query cache", deps.QueryCache); err != nil {
		return fail(err)
	}
	if graphAgentLLMConfigured(cfg.GraphAgentLLM) {
		llm, err := graphagent.NewLLMClientWithSecrets(ctx, graphagent.LLMConfigWithSecrets{
			LLMConfig: graphagent.LLMConfig{
				Provider:       cfg.GraphAgentLLM.Provider,
				Model:          cfg.GraphAgentLLM.Model,
				SonnetModel:    cfg.GraphAgentLLM.SonnetModel,
				OpusModel:      cfg.GraphAgentLLM.OpusModel,
				HaikuModel:     cfg.GraphAgentLLM.HaikuModel,
				Region:         cfg.GraphAgentLLM.BedrockRegion,
				MaxTokens:      cfg.GraphAgentLLM.MaxTokens,
				Temperature:    cfg.GraphAgentLLM.Temperature,
				TemperatureSet: cfg.GraphAgentLLM.TemperatureSet,
			},
			OpenRouterAPIKey: cfg.GraphAgentLLM.OpenRouterAPIKey,
			HTTPDoer:         NewHTTPDoer(),
		})
		if err != nil {
			return fail(fmt.Errorf("open graph agent llm: %w", err))
		}
		deps.GraphAgentLLM = llm
	}
	return deps, closeAll, nil
}

// OpenSourceRuntimeBootstrapDependencies opens only the state-store dependency required to validate and persist source runtime definitions.
func OpenSourceRuntimeBootstrapDependencies(ctx context.Context, cfg config.Config) (Dependencies, func() error, error) {
	var (
		deps    Dependencies
		closers []closer
	)
	closeAll := func() error {
		var errs []error
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dependencyPingTimeout)
		defer cancel()
		for i := len(closers) - 1; i >= 0; i-- {
			if err := closers[i](closeCtx); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	fail := func(err error) (Dependencies, func() error, error) {
		_ = closeAll()
		return Dependencies{}, func() error { return nil }, err
	}
	if cfg.StateStore.Driver == config.StateStoreDriverPostgres {
		stateStore, err := statestorepostgres.Open(cfg.StateStore)
		if err != nil {
			return fail(fmt.Errorf("open state store: %w", err))
		}
		deps.StateStore = stateStore
		closers = append(closers, func(context.Context) error {
			return stateStore.Close()
		})
	}
	if err := pingDependency(ctx, "state store", deps.StateStore); err != nil {
		return fail(err)
	}
	return deps, closeAll, nil
}
func graphAgentLLMConfigured(cfg config.GraphAgentLLMConfig) bool {
	return cfg.Provider != "" || cfg.Model != "" ||
		cfg.SonnetModel != "" || cfg.OpusModel != "" || cfg.HaikuModel != "" ||
		cfg.BedrockRegion != "" || cfg.OpenRouterAPIKey != "" || cfg.MaxTokens != 0 ||
		cfg.TemperatureSet
}

// pingDependency runs Ping with its own dependencyPingTimeout-bounded context so
// the second/third dependency check still gets the full configured budget even
// if an earlier ping consumed most of the original deadline.
func pingDependency(ctx context.Context, label string, dep interface{ Ping(context.Context) error }) error {
	if dep == nil {
		return nil
	}
	pingCtx, cancel := context.WithTimeout(ctx, dependencyPingTimeout)
	defer cancel()
	if err := dep.Ping(pingCtx); err != nil {
		return fmt.Errorf("ping %s: %w", label, err)
	}
	return nil
}
